"""
parser.py
---------
PCAP ingestion, packet parsing, SQLite database loading, and XML export.

Features:
- Primary parser: PyShark (using system tshark)
- Non-main thread event loop handling for Streamlit compatibility
- Automatic fallback: Scapy fallback if tshark is missing or pyshark raises an error
- Missing/malformed layer tolerance (NULL / None defaults)
- Packet capping (max_packets)
- SQLite bulk insert with indexing
- XML export (<capture><packet>...</packet></capture>)
"""

import asyncio
import os
import re
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple


WELL_KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "TLS",
    445: "SMB",
    587: "SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1337: "ELITE",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    4444: "METASPLOIT",
    5432: "POSTGRES",
    5900: "VNC",
    6379: "REDIS",
    6667: "IRC",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    31337: "BACK_ORIFICE",
}


def find_tshark() -> Optional[str]:
    """Locate tshark binary across standard Mac/Linux directories."""
    paths_to_check = [
        shutil.which("tshark"),
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "/bin/tshark",
    ]
    for p in paths_to_check:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            # Ensure folder is in system PATH
            bin_dir = os.path.dirname(p)
            if bin_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{bin_dir}:{os.environ.get('PATH', '')}"
            return p
    return None


def get_tshark_version(tshark_path: str) -> str:
    """Retrieve version string from tshark."""
    try:
        res = subprocess.run([tshark_path, "-v"], capture_output=True, text=True, timeout=5)
        if res.stdout:
            match = re.search(r"TShark \(Wireshark\) ([\d\.]+)", res.stdout)
            if match:
                return match.group(1)
            parts = res.stdout.split()
            if len(parts) >= 3:
                return parts[2]
    except Exception:
        pass
    return "4.x"


def decode_tcp_flags_val(flags_val: Any) -> Optional[str]:
    """Converts int/hex/string TCP flags to human-readable format like SYN-ACK."""
    if flags_val is None:
        return None
    try:
        if isinstance(flags_val, str):
            if flags_val.startswith("0x") or flags_val.startswith("0X"):
                val = int(flags_val, 16)
            elif flags_val.isdigit():
                val = int(flags_val)
            else:
                # String representation (e.g. 'S', 'SA', 'A', 'PA', 'FA', 'RA')
                val = 0
                f_upper = flags_val.upper()
                if "F" in f_upper: val |= 0x01
                if "S" in f_upper: val |= 0x02
                if "R" in f_upper: val |= 0x04
                if "P" in f_upper: val |= 0x08
                if "A" in f_upper: val |= 0x10
                if "U" in f_upper: val |= 0x20
        else:
            val = int(flags_val)

        flag_names = []
        if val & 0x02: flag_names.append("SYN")
        if val & 0x10: flag_names.append("ACK")
        if val & 0x04: flag_names.append("RST")
        if val & 0x01: flag_names.append("FIN")
        if val & 0x08: flag_names.append("PSH")
        if val & 0x20: flag_names.append("URG")

        return "-".join(flag_names) if flag_names else (hex(val) if val != 0 else "NONE")
    except Exception:
        return str(flags_val)


class PacketList(list):
    """Custom list subclass that holds a cap_hit flag."""
    def __init__(self, iterable=None, cap_hit: bool = False):
        super().__init__(iterable or [])
        self.cap_hit = cap_hit


def _parse_with_scapy(path: str, max_packets: int = 20000) -> Tuple[PacketList, str]:
    """Fallback parser using Scapy."""
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS

    packets = PacketList()
    cap_hit = False

    with PcapReader(path) as pcap_reader:
        for idx, pkt in enumerate(pcap_reader, start=1):
            if idx > max_packets:
                cap_hit = True
                break

            ts = float(getattr(pkt, "time", 0.0))
            pkt_len = len(pkt)
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = "OTHER"
            app_protocol = None
            tcp_flags = None

            # IP / Network Layer
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif pkt.haslayer(IPv6):
                ipv6_layer = pkt[IPv6]
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
            elif pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                protocol = "ARP"
                app_protocol = "ARP"

            # Transport Layer
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                protocol = "TCP"
                tcp_flags = decode_tcp_flags_val(int(tcp_layer.flags))
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                protocol = "UDP"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                app_protocol = "ICMP"

            # Application protocol detection via payload and ports
            if pkt.haslayer(DNS):
                app_protocol = "DNS"
            elif protocol in ("TCP", "UDP"):
                for p_num in (dst_port, src_port):
                    if p_num in WELL_KNOWN_PORTS:
                        app_protocol = WELL_KNOWN_PORTS[p_num]
                        break

            if app_protocol is None:
                app_protocol = protocol

            packets.append({
                "packet_no": idx,
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "app_protocol": app_protocol,
                "tcp_flags": tcp_flags,
                "length": pkt_len,
            })

    packets.cap_hit = cap_hit
    return packets, "Scapy fallback"


def _parse_with_pyshark(path: str, tshark_path: str, max_packets: int = 20000) -> Tuple[PacketList, str]:
    """Primary parser using PyShark."""
    import pyshark

    # Streamlit runs scripts in a non-main thread, so create a fresh event loop
    asyncio.set_event_loop(asyncio.new_event_loop())

    version_str = get_tshark_version(tshark_path)
    parser_label = f"PyShark (tshark {version_str})"
    packets = PacketList()
    cap_hit = False

    capture = pyshark.FileCapture(
        path,
        tshark_path=tshark_path,
        keep_packets=False,
    )

    try:
        for idx, p in enumerate(capture, start=1):
            if idx > max_packets:
                cap_hit = True
                break

            try:
                ts = float(p.sniff_timestamp)
            except Exception:
                ts = float(getattr(p, "sniff_time", 0.0).timestamp() if hasattr(p, "sniff_time") else 0.0)

            try:
                pkt_len = int(p.length)
            except Exception:
                pkt_len = 0

            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = "OTHER"
            app_proto = None
            tcp_flags = None

            # IP / Network
            if "ip" in p:
                src_ip = getattr(p.ip, "src", None)
                dst_ip = getattr(p.ip, "dst", None)
            elif "ipv6" in p:
                src_ip = getattr(p.ipv6, "src", None)
                dst_ip = getattr(p.ipv6, "dst", None)
            elif "arp" in p:
                src_ip = getattr(p.arp, "src_proto_ipv4", None)
                dst_ip = getattr(p.arp, "dst_proto_ipv4", None)
                protocol = "ARP"
                app_proto = "ARP"

            # Transport
            if "tcp" in p:
                protocol = "TCP"
                try:
                    src_port = int(p.tcp.srcport)
                except Exception:
                    src_port = None
                try:
                    dst_port = int(p.tcp.dstport)
                except Exception:
                    dst_port = None
                raw_flags = getattr(p.tcp, "flags", None)
                tcp_flags = decode_tcp_flags_val(raw_flags)
            elif "udp" in p:
                protocol = "UDP"
                try:
                    src_port = int(p.udp.srcport)
                except Exception:
                    src_port = None
                try:
                    dst_port = int(p.udp.dstport)
                except Exception:
                    dst_port = None
            elif "icmp" in p:
                protocol = "ICMP"
                app_proto = "ICMP"

            # App protocol / highest layer
            highest = getattr(p, "highest_layer", "").upper()
            if highest in ("DATA", "TCP", "UDP", ""):
                # Check for specific layer names
                layer_names = [l.layer_name.upper() for l in getattr(p, "layers", [])]
                if "HTTP" in layer_names:
                    app_proto = "HTTP"
                elif "FTP" in layer_names:
                    app_proto = "FTP"
                elif "TELNET" in layer_names:
                    app_proto = "TELNET"
                elif "SSH" in layer_names:
                    app_proto = "SSH"
                elif "DNS" in layer_names:
                    app_proto = "DNS"
                elif "TLS" in layer_names or "SSL" in layer_names:
                    app_proto = "TLS"
                else:
                    # Look up ports
                    for p_num in (dst_port, src_port):
                        if p_num in WELL_KNOWN_PORTS:
                            app_proto = WELL_KNOWN_PORTS[p_num]
                            break
                    if app_proto is None:
                        app_proto = protocol
            else:
                app_proto = highest

            packets.append({
                "packet_no": idx,
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "app_protocol": app_proto,
                "tcp_flags": tcp_flags,
                "length": pkt_len,
            })
    finally:
        try:
            capture.close()
        except Exception:
            pass

    packets.cap_hit = cap_hit
    return packets, parser_label


def parse_pcap(path: str, max_packets: int = 20000) -> Tuple[PacketList, str]:
    """
    Parses a PCAP file using PyShark if available, falling back to Scapy.
    Returns (list_of_packet_dicts, parser_used_string).
    The returned list has a .cap_hit attribute indicating if max_packets was reached.
    """
    tshark_bin = find_tshark()
    if tshark_bin:
        try:
            packets, parser_used = _parse_with_pyshark(path, tshark_bin, max_packets=max_packets)
            return packets, parser_used
        except Exception as e:
            print(f"[!] PyShark failed with error ({e}). Falling back to Scapy...")

    # Fallback to Scapy
    packets, parser_used = _parse_with_scapy(path, max_packets=max_packets)
    return packets, parser_used


def load_to_sqlite(packets: List[Dict[str, Any]], db_path: str = "packets.db") -> int:
    """
    Creates the packets table in SQLite and bulk-inserts packet records.
    Adds indexes on src_ip, dst_ip, protocol, dst_port, and timestamp.
    Returns the number of rows inserted.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS packets;")
    cur.execute("""
        CREATE TABLE packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_no INTEGER,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            app_protocol TEXT,
            tcp_flags TEXT,
            length INTEGER
        );
    """)

    rows = [
        (
            p.get("packet_no"),
            p.get("timestamp"),
            p.get("src_ip"),
            p.get("dst_ip"),
            p.get("src_port"),
            p.get("dst_port"),
            p.get("protocol"),
            p.get("app_protocol"),
            p.get("tcp_flags"),
            p.get("length"),
        )
        for p in packets
    ]

    cur.executemany(
        """
        INSERT INTO packets (
            packet_no, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, app_protocol, tcp_flags, length
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        rows,
    )

    # Required and performance indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets(dst_port);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);")

    conn.commit()
    conn.close()
    return len(rows)


def export_to_xml(packets: List[Dict[str, Any]], path: str = "packets.xml") -> str:
    """
    Exports parsed packets to XML:
    <capture>
        <packet id="...">
            <packet_no>...</packet_no>
            ...
        </packet>
    </capture>
    """
    root = ET.Element("capture", attrib={"total_packets": str(len(packets))})
    for p in packets:
        pkt_elem = ET.SubElement(root, "packet", attrib={"id": str(p.get("packet_no", ""))})
        for key in (
            "packet_no",
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "app_protocol",
            "tcp_flags",
            "length",
        ):
            sub = ET.SubElement(pkt_elem, key)
            val = p.get(key)
            sub.text = "" if val is None else str(val)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ", level=0)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    print(f"[*] Testing parser on {target}...")
    pkts, parser_str = parse_pcap(target)
    print(f"[+] Parser used: {parser_str}")
    print(f"[+] Parsed {len(pkts)} packets.")
    inserted = load_to_sqlite(pkts, "test_packets.db")
    print(f"[+] Loaded {inserted} rows into SQLite (test_packets.db).")
    xml_out = export_to_xml(pkts, "test_packets.xml")
    print(f"[+] Exported to XML ({xml_out}).")
