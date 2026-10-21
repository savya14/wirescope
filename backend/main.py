"""
backend/main.py
---------------
FastAPI backend service for PCAP Forensic Traffic & Threat Analyzer.
Exposes REST endpoints that wrap parser.py, detection.py, and SQLite database analytics.
"""

import asyncio
import io
import os
import sqlite3
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add repository root to Python path to import existing modules untouched
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from parser import export_to_xml, find_tshark, get_tshark_version, load_to_sqlite, parse_pcap
from detection import run_all_detections

# Paths for shared persistent artifacts
# Each visitor gets an isolated database/XML pair keyed by a session id, so concurrent
# users on a public deployment never overwrite each other's capture.
SESSIONS_DIR = Path(os.environ.get("SESSIONS_DIR", str(BASE_DIR / "data" / "sessions")))
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_MB", "25")) * 1024 * 1024
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
SAMPLE_PCAP_PATH = str(BASE_DIR / "sample.pcap")
SCENARIOS_DIR = str(BASE_DIR / "scenarios")

INSECURE_PORTS = {21, 23, 25, 80, 110, 143, 4444, 31337, 6667, 1337}

# Preset threat scenario definitions
SCENARIOS = [
    {
        "id": "full_attack",
        "name": "Full Attack Chain",
        "description": "All 5 threat signals active: port scan, plaintext protocols, C2 backdoor ports, heavy talker, and ICMP flood.",
        "severity_tag": "CRITICAL",
        "expected_alerts": 5,
    },
    {
        "id": "port_scan",
        "name": "Port Scan",
        "description": "Normal background traffic with a staged SYN port scan from 192.168.1.99 targeting 42 ports.",
        "severity_tag": "HIGH",
        "expected_alerts": 1,
    },
    {
        "id": "malware_c2",
        "name": "Malware C2 & Plaintext",
        "description": "C2 channels on ports 4444, 31337, 6667, 1337 alongside unencrypted HTTP, FTP, and Telnet sessions.",
        "severity_tag": "MEDIUM",
        "expected_alerts": 2,
    },
    {
        "id": "normal",
        "name": "Benign Baseline",
        "description": "Clean network traffic only — DNS, HTTPS, SSH, and ICMP. Zero threat alerts expected.",
        "severity_tag": "CLEAR",
        "expected_alerts": 0,
    },
]

app = FastAPI(
    title="PCAP Analyzer API",
    description="Forensic packet analysis and threat detection backend",
    version="2.0.0",
)

# Enable CORS for frontend Vite development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        o.strip()
        for o in os.environ.get(
            "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if o.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory capture metadata, per session id
SESSION_METADATA: Dict[str, Dict[str, Any]] = {}


def get_sid(
    x_session_id: Optional[str] = Header(None),
    sid: Optional[str] = Query(None, description="Session id (for plain download links)"),
) -> str:
    value = x_session_id or sid
    if not value or not SESSION_ID_RE.match(value):
        raise HTTPException(status_code=400, detail="Missing or invalid session id.")
    return value


def db_path(sid: str) -> str:
    return str(SESSIONS_DIR / f"{sid}.db")


def xml_path(sid: str) -> str:
    return str(SESSIONS_DIR / f"{sid}.xml")


def cleanup_sessions() -> None:
    """Drops session artifacts older than the TTL so disk use stays bounded."""
    cutoff = time.time() - SESSION_TTL_SECONDS
    for f in SESSIONS_DIR.glob("*"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                SESSION_METADATA.pop(f.stem, None)
        except OSError:
            pass


# -----------------------------------------------------------------------------
# Pydantic Schemas
# -----------------------------------------------------------------------------
class MetadataModel(BaseModel):
    parser_used: str
    total_packets: int
    total_bytes: int
    unique_hosts: int
    protocol_count: int
    duration_seconds: float
    alert_count: int
    cap_hit: bool
    capture_name: str


class DetectionModel(BaseModel):
    id: str
    title: str
    severity: str
    summary: str
    evidence: List[Dict[str, Any]]


class ProtocolItem(BaseModel):
    protocol: str
    count: int


class TopTalkerItem(BaseModel):
    src_ip: str
    bytes: int


class TimelineItem(BaseModel):
    second: int
    packets: int
    bytes: int


class PacketSizeItem(BaseModel):
    bucket: str
    count: int


class DstPortItem(BaseModel):
    port: int
    count: int
    insecure: bool


class PortScanPointItem(BaseModel):
    elapsed: float
    dst_port: int
    src_ip: str


class HostFlowItem(BaseModel):
    src_ip: str
    dst_ip: str
    bytes: int


class ConversationMatrix(BaseModel):
    sources: List[str]
    destinations: List[str]
    z: List[List[int]]


class ChartsModel(BaseModel):
    protocol_distribution: List[ProtocolItem]
    top_talkers: List[TopTalkerItem]
    traffic_timeline: List[TimelineItem]
    packet_sizes: List[PacketSizeItem]
    top_dst_ports: List[DstPortItem]
    port_scan_points: List[PortScanPointItem]
    host_flow: List[HostFlowItem]
    conversation_matrix: ConversationMatrix


class AnalysisResponse(BaseModel):
    meta: MetadataModel
    detections: List[DetectionModel]
    charts: ChartsModel


class PacketRow(BaseModel):
    packet_no: int
    timestamp: float
    time_utc: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    app_protocol: Optional[str] = None
    tcp_flags: Optional[str] = None
    length: int


class PaginatedPacketsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    packets: List[PacketRow]


class HealthResponse(BaseModel):
    status: str
    parser_used: str
    packet_count: int
    database_ready: bool


# -----------------------------------------------------------------------------
# Database Helper & Analytics Aggregations
# -----------------------------------------------------------------------------
def get_db_connection(sid: str) -> sqlite3.Connection:
    if not os.path.exists(db_path(sid)):
        raise HTTPException(
            status_code=404,
            detail="packets.db has not been initialized. Please load or analyze a capture first.",
        )
    return sqlite3.connect(db_path(sid))


def compute_dashboard_payload(sid: str, parser_used: str, cap_hit: bool, capture_name: str) -> AnalysisResponse:
    """Executes all analytical SQL queries against packets.db to build the complete dashboard state."""
    conn = get_db_connection(sid)
    try:
        # 1. Metadata KPIs
        kpi_query = """
            SELECT 
                COUNT(*) as total_packets,
                COALESCE(SUM(length), 0) as total_bytes,
                COUNT(DISTINCT protocol) as total_protocols,
                COALESCE(MAX(timestamp) - MIN(timestamp), 0.0) as duration_seconds
            FROM packets;
        """
        kpi_df = pd.read_sql(kpi_query, conn)
        total_packets = int(kpi_df["total_packets"].iloc[0])
        total_bytes = int(kpi_df["total_bytes"].iloc[0])
        total_protocols = int(kpi_df["total_protocols"].iloc[0])
        duration_seconds = round(float(kpi_df["duration_seconds"].iloc[0]), 2)

        # Unique hosts
        unique_hosts_query = """
            SELECT COUNT(DISTINCT ip) as unique_hosts FROM (
                SELECT src_ip as ip FROM packets WHERE src_ip IS NOT NULL
                UNION
                SELECT dst_ip as ip FROM packets WHERE dst_ip IS NOT NULL
            );
        """
        unique_hosts = int(pd.read_sql(unique_hosts_query, conn)["unique_hosts"].iloc[0])

        # 2. Threat Detections
        raw_alerts = run_all_detections(conn)
        detections: List[DetectionModel] = []
        for alert in raw_alerts:
            # For heavy_talkers, qualify only if the dominant host controls > 40% volume share
            if alert.get("id") == "heavy_talkers":
                ev_df = alert.get("evidence")
                if isinstance(ev_df, pd.DataFrame) and not ev_df.empty:
                    top_share = float(ev_df.iloc[0].get("traffic_share_pct", 0))
                    if top_share < 40.0:
                        continue

            evidence_rows: List[Dict[str, Any]] = []
            if "evidence" in alert and isinstance(alert["evidence"], pd.DataFrame):
                # Clean NaNs for JSON serialization
                clean_df = alert["evidence"].fillna("")
                evidence_rows = clean_df.to_dict(orient="records")
            elif "summary" in alert and isinstance(alert["summary"], pd.DataFrame):
                clean_df = alert["summary"].fillna("")
                evidence_rows = clean_df.to_dict(orient="records")

            detections.append(
                DetectionModel(
                    id=alert["id"],
                    title=alert["title"],
                    severity=alert["severity"],
                    summary=alert["detail"],
                    evidence=evidence_rows,
                )
            )

        meta = MetadataModel(
            parser_used=parser_used,
            total_packets=total_packets,
            total_bytes=total_bytes,
            unique_hosts=unique_hosts,
            protocol_count=total_protocols,
            duration_seconds=duration_seconds,
            alert_count=len(detections),
            cap_hit=cap_hit,
            capture_name=capture_name,
        )

        # Update in-memory metadata
        SESSION_METADATA[sid] = {
            "parser_used": parser_used,
            "total_packets": total_packets,
            "cap_hit": cap_hit,
            "capture_name": capture_name,
        }

        # 3. Chart Aggregations
        # A) Protocol distribution
        proto_df = pd.read_sql(
            "SELECT protocol, COUNT(*) as count FROM packets WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY count DESC;",
            conn,
        )
        protocol_distribution = [
            ProtocolItem(protocol=str(r["protocol"]), count=int(r["count"])) for _, r in proto_df.iterrows()
        ]

        # B) Top talkers by bytes (Top 10)
        talkers_df = pd.read_sql(
            "SELECT src_ip, SUM(length) as bytes FROM packets WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY bytes DESC LIMIT 10;",
            conn,
        )
        top_talkers = [
            TopTalkerItem(src_ip=str(r["src_ip"]), bytes=int(r["bytes"])) for _, r in talkers_df.iterrows()
        ]

        # C) Traffic timeline
        timeline_query = """
            SELECT 
                CAST(timestamp - (SELECT MIN(timestamp) FROM packets) AS INT) as second,
                COUNT(*) as packets,
                SUM(length) as bytes
            FROM packets
            GROUP BY second
            ORDER BY second;
        """
        time_df = pd.read_sql(timeline_query, conn)
        traffic_timeline = [
            TimelineItem(second=int(r["second"]), packets=int(r["packets"]), bytes=int(r["bytes"]))
            for _, r in time_df.iterrows()
        ]

        # D) Packet size distribution (binned histogram)
        size_bins_query = """
            SELECT 
                CASE 
                    WHEN length < 100 THEN '<100 B'
                    WHEN length < 300 THEN '100-299 B'
                    WHEN length < 600 THEN '300-599 B'
                    WHEN length < 1000 THEN '600-999 B'
                    WHEN length < 1400 THEN '1000-1399 B'
                    ELSE '1400+ B'
                END as bucket,
                COUNT(*) as count,
                MIN(length) as min_len
            FROM packets
            WHERE length IS NOT NULL
            GROUP BY bucket
            ORDER BY min_len ASC;
        """
        size_df = pd.read_sql(size_bins_query, conn)
        packet_sizes = [
            PacketSizeItem(bucket=str(r["bucket"]), count=int(r["count"])) for _, r in size_df.iterrows()
        ]

        # E) Top destination ports
        ports_df = pd.read_sql(
            "SELECT dst_port as port, COUNT(*) as count FROM packets WHERE dst_port IS NOT NULL GROUP BY dst_port ORDER BY count DESC LIMIT 10;",
            conn,
        )
        top_dst_ports = [
            DstPortItem(
                port=int(r["port"]),
                count=int(r["count"]),
                insecure=int(r["port"]) in INSECURE_PORTS,
            )
            for _, r in ports_df.iterrows()
        ]

        # F) Port scan scatter points
        scan_pts_query = """
            SELECT 
                ROUND(timestamp - (SELECT MIN(timestamp) FROM packets), 2) as elapsed,
                dst_port,
                src_ip
            FROM packets
            WHERE dst_port IS NOT NULL
              AND src_ip IN (
                  SELECT src_ip FROM packets 
                  WHERE dst_port IS NOT NULL 
                  GROUP BY src_ip, dst_ip 
                  HAVING COUNT(DISTINCT dst_port) >= 15
              )
            ORDER BY elapsed ASC
            LIMIT 500;
        """
        scan_df = pd.read_sql(scan_pts_query, conn)
        port_scan_points = [
            PortScanPointItem(elapsed=float(r["elapsed"]), dst_port=int(r["dst_port"]), src_ip=str(r["src_ip"]))
            for _, r in scan_df.iterrows()
        ]

        # G) Host communication flow (Sankey top 20)
        flow_df = pd.read_sql(
            "SELECT src_ip, dst_ip, SUM(length) as bytes FROM packets WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL GROUP BY src_ip, dst_ip ORDER BY bytes DESC LIMIT 20;",
            conn,
        )
        host_flow = [
            HostFlowItem(src_ip=str(r["src_ip"]), dst_ip=str(r["dst_ip"]), bytes=int(r["bytes"]))
            for _, r in flow_df.iterrows()
        ]

        # H) Conversation matrix (src_ip x dst_ip heatmap)
        matrix_query = """
            SELECT src_ip, dst_ip, COUNT(*) as count
            FROM packets
            WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY src_ip, dst_ip
            ORDER BY count DESC
            LIMIT 30;
        """
        matrix_df = pd.read_sql(matrix_query, conn)
        if not matrix_df.empty:
            pivot_df = matrix_df.pivot(index="src_ip", columns="dst_ip", values="count").fillna(0)
            sources = [str(s) for s in pivot_df.index]
            destinations = [str(d) for d in pivot_df.columns]
            z_matrix = [[int(val) for val in row] for row in pivot_df.values]
        else:
            sources, destinations, z_matrix = [], [], []

        conversation_matrix = ConversationMatrix(
            sources=sources,
            destinations=destinations,
            z=z_matrix,
        )

        charts = ChartsModel(
            protocol_distribution=protocol_distribution,
            top_talkers=top_talkers,
            traffic_timeline=traffic_timeline,
            packet_sizes=packet_sizes,
            top_dst_ports=top_dst_ports,
            port_scan_points=port_scan_points,
            host_flow=host_flow,
            conversation_matrix=conversation_matrix,
        )

        return AnalysisResponse(meta=meta, detections=detections, charts=charts)
    finally:
        conn.close()


def process_and_load_pcap(sid: str, pcap_path: str, capture_label: str) -> AnalysisResponse:
    """Invokes parser.py to parse pcap, load to SQLite, export XML, and return analytics."""
    # Ensure fresh asyncio event loop is set for PyShark
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    else:
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

    packets, parser_used = parse_pcap(pcap_path, max_packets=20000)
    cap_hit = getattr(packets, "cap_hit", False)

    # Load to SQLite and export XML
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_sessions()
    load_to_sqlite(packets, db_path(sid))
    export_to_xml(packets, xml_path(sid))

    return compute_dashboard_payload(sid, parser_used, cap_hit, capture_label)


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
def get_health(sid: str = Depends(get_sid)):
    """Returns parser engine in use, packet count, and database health."""
    tshark_bin = find_tshark()
    if tshark_bin:
        ver = get_tshark_version(tshark_bin)
        default_engine = f"PyShark (tshark {ver})"
    else:
        default_engine = "Scapy fallback"

    meta = SESSION_METADATA.get(sid, {})
    engine = meta.get("parser_used") or default_engine
    pkt_count = meta.get("total_packets", 0)

    # Check if DB exists and has packets
    db_ready = False
    if os.path.exists(db_path(sid)):
        try:
            conn = sqlite3.connect(db_path(sid))
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM packets;")
            pkt_count = c.fetchone()[0]
            db_ready = True
            conn.close()
        except Exception:
            db_ready = False

    return HealthResponse(
        status="ok",
        parser_used=engine,
        packet_count=pkt_count,
        database_ready=db_ready,
    )


@app.get("/api/sample", response_model=AnalysisResponse)
def get_sample_analysis(sid: str = Depends(get_sid)):
    """Runs the full pipeline on bundled sample.pcap and returns the full JSON dashboard payload."""
    if not os.path.exists(SAMPLE_PCAP_PATH):
        # Generate sample capture if missing
        from generate_sample import create_sample_pcap
        create_sample_pcap(SAMPLE_PCAP_PATH)

    try:
        return process_and_load_pcap(sid, SAMPLE_PCAP_PATH, "sample.pcap (Synthetic Threat Lab)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze sample.pcap: {str(e)}")


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_uploaded_pcap(file: Optional[UploadFile] = File(None), sid: str = Depends(get_sid)):
    """Accepts an uploaded .pcap or .pcapng file, processes it, and returns the dashboard payload."""
    if file is None or not file.filename:
        # Fall back to sample.pcap
        return get_sample_analysis(sid)

    suffix = Path(file.filename).suffix.lower()
    if suffix not in [".pcap", ".pcapng", ".cap"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{suffix}'. Only .pcap and .pcapng captures are supported.",
        )

    # Persist uploaded file to temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            os.remove(temp_file.name)
            raise HTTPException(
                status_code=413,
                detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
            )
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded capture file is empty.")
        temp_file.write(content)
        temp_path = temp_file.name

    try:
        return process_and_load_pcap(sid, temp_path, file.filename)
    except HTTPException:
        raise
    except Exception as e:
        # The only variable input here is the visitor's file, so treat failures as a bad capture.
        raise HTTPException(status_code=400, detail=f"Capture parsing failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.get("/api/packets", response_model=PaginatedPacketsResponse)
def get_packets(
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g. TCP, UDP, ICMP)"),
    search: Optional[str] = Query(None, description="Search by Source or Destination IP"),
    port: Optional[int] = Query(None, description="Filter by Source or Destination Port"),
    host: Optional[str] = Query(None, description="Exact Source or Destination IP match"),
    src: Optional[str] = Query(None, description="Exact Source IP match (flow filter)"),
    dst: Optional[str] = Query(None, description="Exact Destination IP match (flow filter)"),
    alert: Optional[str] = Query(None, description="Restrict to the evidence packets of a detection id"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    sid: str = Depends(get_sid),
):
    """Returns paginated packet rows with query filters, backed by SQLite SQL queries."""
    conn = get_db_connection(sid)
    try:
        sql_clauses = ["1=1"]
        sql_params: List[Any] = []

        if protocol and protocol.strip():
            sql_clauses.append("UPPER(protocol) = ?")
            sql_params.append(protocol.strip().upper())

        if search and search.strip():
            clean_search = f"%{search.strip()}%"
            sql_clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            sql_params.extend([clean_search, clean_search])

        if port and port > 0:
            sql_clauses.append("(src_port = ? OR dst_port = ?)")
            sql_params.extend([port, port])

        if host and host.strip():
            sql_clauses.append("(src_ip = ? OR dst_ip = ?)")
            sql_params.extend([host.strip(), host.strip()])

        if src and src.strip():
            sql_clauses.append("src_ip = ?")
            sql_params.append(src.strip())

        if dst and dst.strip():
            sql_clauses.append("dst_ip = ?")
            sql_params.append(dst.strip())

        if alert and alert.strip():
            # Evidence frames come from the detection itself; host-level
            # detections (heavy talkers) carry no packet numbers, so match their hosts.
            match = next((a for a in run_all_detections(conn) if a.get("id") == alert.strip()), None)
            ev = match.get("evidence") if match else None
            if ev is not None and "packet_no" in ev.columns:
                nums = [int(n) for n in ev["packet_no"].tolist()]
                sql_clauses.append(f"packet_no IN ({','.join('?' * len(nums)) or 'NULL'})")
                sql_params.extend(nums)
            elif ev is not None and "src_ip" in ev.columns:
                ips = [str(i) for i in ev["src_ip"].tolist()]
                sql_clauses.append(f"src_ip IN ({','.join('?' * len(ips)) or 'NULL'})")
                sql_params.extend(ips)
            else:
                sql_clauses.append("0=1")

        where_stmt = " AND ".join(sql_clauses)

        # Count total matches
        count_query = f"SELECT COUNT(*) FROM packets WHERE {where_stmt};"
        cur = conn.cursor()
        cur.execute(count_query, sql_params)
        total_count = cur.fetchone()[0]

        # Select paginated slice
        select_query = f"""
            SELECT 
                packet_no,
                timestamp,
                datetime(timestamp, 'unixepoch') as time_utc,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                app_protocol,
                tcp_flags,
                length
            FROM packets
            WHERE {where_stmt}
            ORDER BY packet_no ASC
            LIMIT ? OFFSET ?;
        """
        slice_params = sql_params + [limit, offset]
        df_page = pd.read_sql(select_query, conn, params=slice_params).fillna("")

        packet_rows = [
            PacketRow(
                packet_no=int(r["packet_no"]),
                timestamp=float(r["timestamp"]),
                time_utc=str(r["time_utc"]),
                src_ip=str(r["src_ip"]) if r["src_ip"] else None,
                src_port=int(r["src_port"]) if r["src_port"] != "" else None,
                dst_ip=str(r["dst_ip"]) if r["dst_ip"] else None,
                dst_port=int(r["dst_port"]) if r["dst_port"] != "" else None,
                protocol=str(r["protocol"]) if r["protocol"] else None,
                app_protocol=str(r["app_protocol"]) if r["app_protocol"] else None,
                tcp_flags=str(r["tcp_flags"]) if r["tcp_flags"] else None,
                length=int(r["length"]),
            )
            for _, r in df_page.iterrows()
        ]

        return PaginatedPacketsResponse(
            total=total_count,
            limit=limit,
            offset=offset,
            packets=packet_rows,
        )
    finally:
        conn.close()


@app.get("/api/download/{artifact}")
def download_artifact(artifact: str, sid: str = Depends(get_sid)):
    """Serves packets.db, packets.xml, or generated packets.csv for download."""
    clean_art = artifact.lower().strip()

    if clean_art in ["db", "packets.db"]:
        if not os.path.exists(db_path(sid)):
            raise HTTPException(status_code=404, detail="packets.db not found. Please analyze a capture first.")
        return FileResponse(
            path=db_path(sid),
            filename="packets.db",
            media_type="application/x-sqlite3",
        )

    elif clean_art in ["xml", "packets.xml"]:
        if not os.path.exists(xml_path(sid)):
            raise HTTPException(status_code=404, detail="packets.xml not found. Please analyze a capture first.")
        return FileResponse(
            path=xml_path(sid),
            filename="packets.xml",
            media_type="application/xml",
        )

    elif clean_art in ["csv", "packets.csv"]:
        conn = get_db_connection(sid)
        try:
            df = pd.read_sql("SELECT * FROM packets ORDER BY packet_no ASC;", conn)
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            csv_str = csv_buffer.getvalue()
            return Response(
                content=csv_str,
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="packets.csv"'},
            )
        finally:
            conn.close()

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid artifact '{artifact}'. Available artifacts: 'packets.db', 'packets.xml', 'packets.csv'.",
        )


# -----------------------------------------------------------------------------
# Scenario Endpoints
# -----------------------------------------------------------------------------
class ScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    severity_tag: str
    expected_alerts: int


@app.get("/api/scenarios", response_model=List[ScenarioInfo])
def list_scenarios():
    """Returns metadata for all available preset threat scenarios."""
    return [ScenarioInfo(**s) for s in SCENARIOS]


@app.get("/api/scenario/{scenario_id}", response_model=AnalysisResponse)
def analyze_scenario(scenario_id: str, sid: str = Depends(get_sid)):
    """Runs the full pipeline on a preset scenario pcap and returns the dashboard payload."""
    # Validate scenario ID
    scenario = None
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            scenario = s
            break
    if scenario is None:
        valid_ids = [s["id"] for s in SCENARIOS]
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{scenario_id}' not found. Valid: {valid_ids}",
        )

    pcap_path = os.path.join(SCENARIOS_DIR, f"{scenario_id}.pcap")
    if not os.path.exists(pcap_path):
        # Try generating scenarios on-the-fly
        try:
            from generate_scenarios import generate_all_scenarios
            generate_all_scenarios(SCENARIOS_DIR)
        except Exception as gen_err:
            raise HTTPException(
                status_code=500,
                detail=f"Scenario pcap not found and generation failed: {gen_err}",
            )
        if not os.path.exists(pcap_path):
            raise HTTPException(
                status_code=500,
                detail=f"Scenario pcap '{scenario_id}.pcap' could not be generated.",
            )

    try:
        capture_label = f"{scenario['name']} ({scenario_id}.pcap)"
        return process_and_load_pcap(sid, pcap_path, capture_label)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scenario analysis failed: {str(e)}")


# -----------------------------------------------------------------------------
# Single-service deployment: serve the built React app from the same origin.
# Mounted last so every /api route above takes precedence.
# -----------------------------------------------------------------------------
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
