"""
detection.py
------------
Threat signal detection engine for network PCAP analysis using SQL and pandas.

Implements 5 core threat signals:
1. Port scan suspects (HIGH): Source IPs contacting >= 15 distinct destination ports on a single host.
2. Plaintext / Insecure protocols (MEDIUM): Traffic on 21, 23, 80, 110, 143, 25, or app_protocol HTTP/FTP/TELNET.
3. Suspicious / Backdoor ports (MEDIUM): Known exploit or C2 ports (4444, 31337, 6667, 1337).
4. Heavy talkers (LOW / INFO): Hosts above the 95th percentile of bytes sent, with traffic share.
5. ICMP volume (LOW): Anomalous ICMP count/flood.
"""

import sqlite3
from typing import Any, Dict, List, Optional, Union
import pandas as pd


def get_connection(conn_or_db: Union[sqlite3.Connection, str]) -> sqlite3.Connection:
    if isinstance(conn_or_db, str):
        return sqlite3.connect(conn_or_db)
    return conn_or_db


def detect_port_scans(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """
    Signal 1: Port Scan Suspects (Severity: HIGH)
    Detects source IPs contacting at least 15 distinct destination ports on a single destination.
    Prioritizes SYN scan initiators, falling back to general multi-port probes.
    """
    query_syn = """
        SELECT 
            src_ip, 
            dst_ip, 
            COUNT(DISTINCT dst_port) as distinct_ports,
            COUNT(*) as total_probes,
            MIN(timestamp) as scan_start,
            MAX(timestamp) as scan_end
        FROM packets
        WHERE dst_port IS NOT NULL 
          AND src_ip IS NOT NULL 
          AND dst_ip IS NOT NULL
          AND (tcp_flags LIKE '%SYN%' AND tcp_flags NOT LIKE '%ACK%')
        GROUP BY src_ip, dst_ip
        HAVING distinct_ports >= 15
        ORDER BY distinct_ports DESC;
    """
    df = pd.read_sql_query(query_syn, conn)
    if df.empty:
        # Fallback for general scans (e.g. UDP or captures where flags are absent)
        fallback_query = """
            SELECT 
                src_ip, 
                dst_ip, 
                COUNT(DISTINCT dst_port) as distinct_ports,
                COUNT(*) as total_probes,
                MIN(timestamp) as scan_start,
                MAX(timestamp) as scan_end
            FROM packets
            WHERE dst_port IS NOT NULL AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY src_ip, dst_ip
            HAVING distinct_ports >= 15
            ORDER BY distinct_ports DESC;
        """
        df = pd.read_sql_query(fallback_query, conn)

    if df.empty:
        return None

    suspects_summary = []
    for _, row in df.iterrows():
        suspects_summary.append(
            f"{row['src_ip']} contacted {int(row['distinct_ports'])} ports on {row['dst_ip']} ({int(row['total_probes'])} probes)"
        )

    # Fetch detailed probe evidence rows for the suspect(s)
    suspect_ips = df["src_ip"].tolist()
    placeholders = ",".join(["?"] * len(suspect_ips))
    evidence_query = f"""
        SELECT 
            packet_no,
            datetime(timestamp, 'unixepoch') as time_utc,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            length
        FROM packets
        WHERE src_ip IN ({placeholders}) AND dst_port IS NOT NULL
        ORDER BY timestamp
        LIMIT 100;
    """
    evidence_df = pd.read_sql_query(evidence_query, conn, params=suspect_ips)

    return {
        "id": "port_scan",
        "severity": "HIGH",
        "title": "Port Scan Suspects Detected",
        "detail": f"Identified {len(df)} host(s) scanning >=15 distinct ports on a target: {'; '.join(suspects_summary)}.",
        "evidence": evidence_df,
        "summary": df,
    }


def detect_plaintext_protocols(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """
    Signal 2: Plaintext / Insecure Protocols (Severity: MEDIUM)
    Traffic on ports 21 (FTP), 23 (Telnet), 80 (HTTP), 110 (POP3), 143 (IMAP), 25 (SMTP)
    or app_protocol of HTTP, FTP, TELNET.
    """
    query = """
        SELECT 
            packet_no,
            datetime(timestamp, 'unixepoch') as time_utc,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            app_protocol,
            length
        FROM packets
        WHERE dst_port IN (21, 23, 25, 80, 110, 143)
           OR src_port IN (21, 23, 25, 80, 110, 143)
           OR UPPER(app_protocol) IN ('HTTP', 'FTP', 'TELNET', 'POP3', 'IMAP', 'SMTP')
        ORDER BY timestamp;
    """
    evidence_df = pd.read_sql_query(query, conn)
    if evidence_df.empty:
        return None

    # Identify all distinct hosts involved
    hosts = set(evidence_df["src_ip"].dropna()).union(set(evidence_df["dst_ip"].dropna()))
    protocols_found = set(evidence_df["app_protocol"].dropna().str.upper())
    ports_found = set(evidence_df["dst_port"].dropna().astype(int)).union(
        set(evidence_df["src_port"].dropna().astype(int))
    ).intersection({21, 23, 25, 80, 110, 143})

    proto_list = ", ".join(sorted(protocols_found)) if protocols_found else "Plaintext"
    ports_list = ", ".join(str(p) for p in sorted(ports_found))

    detail = (
        f"Detected {len(evidence_df)} packet(s) transmitting unencrypted protocols ({proto_list} on ports {ports_list}) "
        f"across {len(hosts)} host(s): {', '.join(sorted(hosts)[:6])}."
    )

    return {
        "id": "plaintext_protocols",
        "severity": "MEDIUM",
        "title": "Plaintext / Insecure Protocols Detected",
        "detail": detail,
        "evidence": evidence_df,
        "hosts": sorted(hosts),
    }


def detect_suspicious_ports(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """
    Signal 3: Suspicious & Backdoor Ports (Severity: MEDIUM)
    Traffic to known-bad or unusual ports:
    4444 (Metasploit default listener), 31337 (Back Orifice backdoor),
    6667 (IRC C2 botnet), 1337 (Elite backdoor).
    """
    query = """
        SELECT 
            packet_no,
            datetime(timestamp, 'unixepoch') as time_utc,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            app_protocol,
            length
        FROM packets
        WHERE dst_port IN (4444, 31337, 6667, 1337)
           OR src_port IN (4444, 31337, 6667, 1337)
        ORDER BY timestamp;
    """
    evidence_df = pd.read_sql_query(query, conn)
    if evidence_df.empty:
        return None

    ports_hit = set(evidence_df["dst_port"].dropna().astype(int)).union(
        set(evidence_df["src_port"].dropna().astype(int))
    ).intersection({4444, 31337, 6667, 1337})

    port_names = {
        4444: "Metasploit Shell (4444)",
        31337: "Back Orifice C2 (31337)",
        6667: "IRC Botnet C2 (6667)",
        1337: "Elite Backdoor (1337)",
    }
    labeled_ports = [port_names.get(p, str(p)) for p in sorted(ports_hit)]

    detail = (
        f"Observed {len(evidence_df)} packet(s) communicating across known exploit, backdoor, or botnet C2 channels: "
        f"{', '.join(labeled_ports)}."
    )

    return {
        "id": "suspicious_ports",
        "severity": "MEDIUM",
        "title": "Suspicious / C2 Backdoor Ports Active",
        "detail": detail,
        "evidence": evidence_df,
    }


def detect_heavy_talkers(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """
    Signal 4: Heavy Talkers (Severity: LOW / INFO)
    Hosts above the 95th percentile of bytes sent, displaying their share of total traffic.
    """
    query = """
        SELECT 
            src_ip,
            SUM(length) as bytes_sent,
            COUNT(*) as packet_count
        FROM packets
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY bytes_sent DESC;
    """
    df = pd.read_sql_query(query, conn)
    if df.empty or len(df) < 2:
        return None

    total_bytes = df["bytes_sent"].sum()
    if total_bytes == 0:
        return None

    p95 = df["bytes_sent"].quantile(0.95)
    heavy_df = df[df["bytes_sent"] >= p95].copy()
    if heavy_df.empty:
        heavy_df = df.head(1).copy()

    heavy_df["traffic_share_pct"] = (heavy_df["bytes_sent"] / total_bytes * 100.0).round(2)

    top_host = heavy_df.iloc[0]["src_ip"]
    top_bytes = int(heavy_df.iloc[0]["bytes_sent"])
    top_share = heavy_df.iloc[0]["traffic_share_pct"]

    detail = (
        f"Dominant host {top_host} transmitted {top_bytes:,} bytes, accounting for {top_share}% of total capture volume "
        f"(exceeding 95th percentile threshold of {int(p95):,} bytes)."
    )

    # Format human readable size for display
    def format_bytes(b):
        if b >= 1024 * 1024:
            return f"{b / (1024*1024):.2f} MB"
        elif b >= 1024:
            return f"{b / 1024:.2f} KB"
        return f"{b} B"

    display_df = heavy_df.copy()
    display_df["data_volume"] = display_df["bytes_sent"].apply(format_bytes)

    return {
        "id": "heavy_talkers",
        "severity": "LOW",
        "title": "Heavy Talker Traffic Anomaly",
        "detail": detail,
        "evidence": display_df[["src_ip", "data_volume", "packet_count", "traffic_share_pct"]],
    }


def detect_icmp_volume(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """
    Signal 5: ICMP Volume / Ping Sweep Anomaly (Severity: LOW)
    Flags hosts transmitting unusually high ICMP counts (e.g. >= 15 packets or > 3x average).
    """
    query = """
        SELECT 
            src_ip,
            COUNT(*) as icmp_packets,
            COUNT(DISTINCT dst_ip) as distinct_destinations,
            SUM(length) as total_icmp_bytes
        FROM packets
        WHERE UPPER(protocol) = 'ICMP' OR UPPER(app_protocol) = 'ICMP'
        GROUP BY src_ip
        ORDER BY icmp_packets DESC;
    """
    df = pd.read_sql_query(query, conn)
    if df.empty:
        return None

    # Flag if host sent >= 15 ICMP packets
    flagged = df[df["icmp_packets"] >= 15].copy()
    if flagged.empty:
        # Check relative threshold
        avg_icmp = df["icmp_packets"].mean()
        flagged = df[df["icmp_packets"] >= max(5, avg_icmp * 2.5)].copy()

    if flagged.empty:
        return None

    suspect_rows = []
    for _, r in flagged.iterrows():
        suspect_rows.append(f"{r['src_ip']} ({int(r['icmp_packets'])} ICMP pkts to {int(r['distinct_destinations'])} host(s))")

    detail = (
        f"High ICMP volume flagged: {'; '.join(suspect_rows)}. "
        f"Indicates possible ICMP echo sweep, reconnaissance, or low-rate DoS activity."
    )

    evidence_query = """
        SELECT 
            packet_no,
            datetime(timestamp, 'unixepoch') as time_utc,
            src_ip,
            dst_ip,
            protocol,
            length
        FROM packets
        WHERE (UPPER(protocol) = 'ICMP' OR UPPER(app_protocol) = 'ICMP')
        ORDER BY timestamp
        LIMIT 100;
    """
    evidence_df = pd.read_sql_query(evidence_query, conn)

    return {
        "id": "icmp_volume",
        "severity": "LOW",
        "title": "Elevated ICMP Traffic / Sweep Pattern",
        "detail": detail,
        "evidence": evidence_df,
    }


def run_all_detections(conn_or_db: Union[sqlite3.Connection, str]) -> List[Dict[str, Any]]:
    """
    Executes all 5 threat signal detection modules against SQLite.
    Returns a list of triggered alert dictionaries.
    """
    conn = get_connection(conn_or_db)
    close_needed = isinstance(conn_or_db, str)

    alerts = []
    try:
        detectors = [
            detect_port_scans,
            detect_plaintext_protocols,
            detect_suspicious_ports,
            detect_heavy_talkers,
            detect_icmp_volume,
        ]
        for detector in detectors:
            result = detector(conn)
            if result:
                alerts.append(result)
    finally:
        if close_needed:
            conn.close()

    return alerts


if __name__ == "__main__":
    import sys
    from parser import parse_pcap, load_to_sqlite

    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    print(f"[*] Parsing {pcap_path}...")
    pkts, p_used = parse_pcap(pcap_path)
    load_to_sqlite(pkts, "detection_test.db")

    conn = sqlite3.connect("detection_test.db")
    alerts = run_all_detections(conn)
    conn.close()
    import os
    os.remove("detection_test.db")

    print(f"\n[+] Total alerts triggered: {len(alerts)}")
    for a in alerts:
        print(f" -> [{a['severity']}] {a['title']}: {a['detail']}")
