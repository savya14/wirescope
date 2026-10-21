#!/usr/bin/env python3
"""
generate_scenarios.py
---------------------
Creates four distinct scenario .pcap files in scenarios/ directory,
each designed to trigger different subsets of the 5 threat detections.

Scenarios:
  1. normal.pcap      - Benign traffic only, zero threat alerts.
  2. port_scan.pcap   - Normal bg + staged SYN port scan (HIGH alert).
  3. malware_c2.pcap  - Normal bg + C2/backdoor ports + plaintext protocols (MEDIUM alerts).
  4. full_attack.pcap - All 5 threat signals, same as sample.pcap.
"""

import os
import random

from scapy.config import conf
conf.verb = 0

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap,
)


# ── Shared helper: generate benign background traffic ──────────────────────

def _generate_benign_traffic(base_time: float, packet_count_target: int = 200):
    """Generate clean, normal-looking network traffic with no threat signals."""
    packets = []

    internal_hosts = [
        "192.168.1.10", "192.168.1.25", "192.168.1.42",
        "192.168.1.50", "192.168.1.55", "192.168.1.100",
        "192.168.1.150", "192.168.1.200",
    ]
    gateway_ip = "192.168.1.1"
    gateway_mac = "52:54:00:12:34:56"
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    external_web_ips = ["93.184.216.34", "104.244.42.1", "151.101.1.69", "140.82.112.4"]
    client_mac = "00:50:56:c0:00:08"
    server_mac = "00:50:56:c0:00:01"

    # ARP (~16 pkts)
    for i, host in enumerate(internal_hosts):
        t = base_time + 0.6 * i
        mac = f"00:16:3e:{i+10:02x}:{i+20:02x}:{i+30:02x}"
        p1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
            op=1, psrc=host, pdst=gateway_ip, hwsrc=mac, hwdst="00:00:00:00:00:00"
        )
        p1.time = t
        packets.append(p1)
        p2 = Ether(dst=mac, src=gateway_mac) / ARP(
            op=2, psrc=gateway_ip, pdst=host, hwsrc=gateway_mac, hwdst=mac
        )
        p2.time = t + 0.002
        packets.append(p2)

    # DNS (~96 pkts)
    domains = [
        "api.github.com", "cloudflare.com", "updates.security.org",
        "cdn.example.net", "mail.google.com", "pypi.org",
    ]
    for i, domain in enumerate(domains * 8):
        client = internal_hosts[i % len(internal_hosts)]
        dns_server = dns_servers[i % len(dns_servers)]
        t_req = base_time + 2.0 + (i * 1.8)
        sport = 49152 + (i * 73) % 15000

        p_req = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=dns_server) / UDP(sport=sport, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="A")
        )
        p_req.time = t_req
        packets.append(p_req)

        p_res = Ether(src=gateway_mac, dst=client_mac) / IP(src=dns_server, dst=client) / UDP(sport=53, dport=sport) / DNS(
            qr=1, aa=1, rd=1, qd=DNSQR(qname=domain, qtype="A"),
            an=DNSRR(rrname=domain, rdata="93.184.216.34", ttl=300)
        )
        p_res.time = t_req + 0.018
        packets.append(p_res)

    # HTTPS sessions (~216 pkts)
    for i in range(36):
        client = internal_hosts[(i * 3) % len(internal_hosts)]
        ext_ip = external_web_ips[i % len(external_web_ips)]
        sport = 50000 + i * 117
        t_start = base_time + 6.0 + (i * 2.3)

        syn = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="S", seq=1000)
        syn.time = t_start
        packets.append(syn)

        synack = Ether(src=gateway_mac, dst=client_mac) / IP(src=ext_ip, dst=client) / TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=1001)
        synack.time = t_start + 0.02
        packets.append(synack)

        ack = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=5001)
        ack.time = t_start + 0.022
        packets.append(ack)

        tls_data = b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03" + os.urandom(120)
        data1 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001) / Raw(load=tls_data)
        data1.time = t_start + 0.03
        packets.append(data1)

        server_tls = b"\x16\x03\x03\x01\x20\x02\x00\x00" + os.urandom(480)
        data2 = Ether(src=gateway_mac, dst=client_mac) / IP(src=ext_ip, dst=client) / TCP(sport=443, dport=sport, flags="PA", seq=5001, ack=1001 + len(tls_data)) / Raw(load=server_tls)
        data2.time = t_start + 0.06
        packets.append(data2)

        ack2 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001 + len(tls_data), ack=5001 + len(server_tls))
        ack2.time = t_start + 0.065
        packets.append(ack2)

    # SSH session (~15 pkts)
    ssh_client = "192.168.1.25"
    ssh_server = "192.168.1.50"
    ssh_sport = 54321
    t_ssh = base_time + 12.0

    ssh_syn = Ether(src=client_mac, dst=server_mac) / IP(src=ssh_client, dst=ssh_server) / TCP(sport=ssh_sport, dport=22, flags="S", seq=200)
    ssh_syn.time = t_ssh
    packets.append(ssh_syn)

    ssh_sa = Ether(src=server_mac, dst=client_mac) / IP(src=ssh_server, dst=ssh_client) / TCP(sport=22, dport=ssh_sport, flags="SA", seq=700, ack=201)
    ssh_sa.time = t_ssh + 0.005
    packets.append(ssh_sa)

    ssh_ack = Ether(src=client_mac, dst=server_mac) / IP(src=ssh_client, dst=ssh_server) / TCP(sport=ssh_sport, dport=22, flags="A", seq=201, ack=701)
    ssh_ack.time = t_ssh + 0.007
    packets.append(ssh_ack)

    b1 = Ether(src=server_mac, dst=client_mac) / IP(src=ssh_server, dst=ssh_client) / TCP(sport=22, dport=ssh_sport, flags="PA", seq=701, ack=201) / Raw(load=b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n")
    b1.time = t_ssh + 0.015
    packets.append(b1)

    b2 = Ether(src=client_mac, dst=server_mac) / IP(src=ssh_client, dst=ssh_server) / TCP(sport=ssh_sport, dport=22, flags="PA", seq=201, ack=701 + len(b1[Raw].load)) / Raw(load=b"SSH-2.0-OpenSSH_9.0\r\n")
    b2.time = t_ssh + 0.02
    packets.append(b2)

    for step in range(10):
        enc_payload = os.urandom(random.randint(64, 256))
        p_ssh = Ether(src=client_mac, dst=server_mac) / IP(src=ssh_client, dst=ssh_server) / TCP(sport=ssh_sport, dport=22, flags="PA") / Raw(load=enc_payload)
        p_ssh.time = t_ssh + 1.0 + step * 2.5
        packets.append(p_ssh)

    # Normal ICMP pings (small count, < 15 so NO alert triggers) ~10 pkts
    for seq_num in range(5):
        t_pkt = base_time + 50.0 + seq_num * 5.0
        req = Ether(src=client_mac, dst=gateway_mac) / IP(src="192.168.1.10", dst=gateway_ip) / ICMP(type=8, code=0, id=0xABCD, seq=seq_num) / Raw(load=b"NormalPing" * 2)
        req.time = t_pkt
        packets.append(req)
        rep = Ether(src=gateway_mac, dst=client_mac) / IP(src=gateway_ip, dst="192.168.1.10") / ICMP(type=0, code=0, id=0xABCD, seq=seq_num) / Raw(load=b"NormalPing" * 2)
        rep.time = t_pkt + 0.003
        packets.append(rep)

    # Ambient background (~120 pkts)
    for extra_i in range(120):
        t_amb = base_time + 1.0 + (extra_i * 0.7)
        s_ip = internal_hosts[extra_i % len(internal_hosts)]
        d_ip = external_web_ips[extra_i % len(external_web_ips)]
        sp = 51000 + extra_i * 19
        p_amb = Ether(src=client_mac, dst=gateway_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=443, flags="PA") / Raw(load=os.urandom(random.randint(60, 300)))
        p_amb.time = t_amb
        packets.append(p_amb)

    return packets


# ── Scenario 1: Normal (benign only) ──────────────────────────────────────

def create_normal_pcap(output_path: str, base_time: float = 1714000000.0):
    packets = _generate_benign_traffic(base_time)
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)
    print(f"  [+] normal.pcap: {len(packets)} packets ({os.path.getsize(output_path)/1024:.1f} KB)")
    return len(packets)


# ── Scenario 2: Port Scan ─────────────────────────────────────────────────

def create_port_scan_pcap(output_path: str, base_time: float = 1714000000.0):
    packets = _generate_benign_traffic(base_time)
    client_mac = "00:50:56:c0:00:08"
    server_mac = "00:50:56:c0:00:01"

    scanner_ip = "192.168.1.99"
    target_ip = "192.168.1.50"
    # 42 ports (all >= 15 threshold, avoiding plaintext ports 21, 23, 25, 80, 110, 143)
    scan_ports = [
        135, 139, 389, 443, 445, 465, 587, 636, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
        8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
        50000, 8081, 9090, 5000, 3000, 7001, 7002, 8088,
        8880, 9042, 9092, 9999, 10000, 10080, 11000, 12000,
    ]

    scan_start_time = base_time + 25.0
    for idx, port in enumerate(scan_ports):
        t_probe = scan_start_time + (idx * 0.08)
        src_port = 40000 + idx
        syn_pkt = Ether(src=client_mac, dst=server_mac) / IP(src=scanner_ip, dst=target_ip) / TCP(sport=src_port, dport=port, flags="S", seq=10000 + idx)
        syn_pkt.time = t_probe
        packets.append(syn_pkt)

        if port in [22, 80, 443]:
            rep = Ether(src=server_mac, dst=client_mac) / IP(src=target_ip, dst=scanner_ip) / TCP(sport=port, dport=src_port, flags="SA", seq=50000, ack=10001 + idx)
        else:
            rep = Ether(src=server_mac, dst=client_mac) / IP(src=target_ip, dst=scanner_ip) / TCP(sport=port, dport=src_port, flags="RA", seq=0, ack=10001 + idx)
        rep.time = t_probe + 0.002
        packets.append(rep)

    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)
    print(f"  [+] port_scan.pcap: {len(packets)} packets ({os.path.getsize(output_path)/1024:.1f} KB)")
    return len(packets)


# ── Scenario 3: Malware C2 ────────────────────────────────────────────────

def create_malware_c2_pcap(output_path: str, base_time: float = 1714000000.0):
    packets = _generate_benign_traffic(base_time)
    client_mac = "00:50:56:c0:00:08"
    gateway_mac = "52:54:00:12:34:56"
    server_mac = "00:50:56:c0:00:01"

    # Plaintext HTTP
    http_client = "192.168.1.10"
    web_server = "93.184.216.34"
    t_http = base_time + 32.0
    h_sport = 48210

    h_syn = Ether(src=client_mac, dst=gateway_mac) / IP(src=http_client, dst=web_server) / TCP(sport=h_sport, dport=80, flags="S")
    h_syn.time = t_http
    packets.append(h_syn)

    h_sa = Ether(src=gateway_mac, dst=client_mac) / IP(src=web_server, dst=http_client) / TCP(sport=80, dport=h_sport, flags="SA")
    h_sa.time = t_http + 0.01
    packets.append(h_sa)

    h_ack = Ether(src=client_mac, dst=gateway_mac) / IP(src=http_client, dst=web_server) / TCP(sport=h_sport, dport=80, flags="A")
    h_ack.time = t_http + 0.012
    packets.append(h_ack)

    http_req = (
        b"GET /admin/login.php?user=root HTTP/1.1\r\n"
        b"Host: 93.184.216.34\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    p_hreq = Ether(src=client_mac, dst=gateway_mac) / IP(src=http_client, dst=web_server) / TCP(sport=h_sport, dport=80, flags="PA") / Raw(load=http_req)
    p_hreq.time = t_http + 0.02
    packets.append(p_hreq)

    # FTP
    ftp_client = "192.168.1.150"
    ftp_server = "192.168.1.50"
    t_ftp = base_time + 35.0
    f_sport = 42100
    f_syn = Ether(src=client_mac, dst=server_mac) / IP(src=ftp_client, dst=ftp_server) / TCP(sport=f_sport, dport=21, flags="S")
    f_syn.time = t_ftp
    packets.append(f_syn)

    f_cmds = [
        (ftp_server, ftp_client, 21, f_sport, b"220 ProFTPD 1.3.5 Server ready.\r\n"),
        (ftp_client, ftp_server, f_sport, 21, b"USER anonymous\r\n"),
        (ftp_server, ftp_client, 21, f_sport, b"331 Guest login ok.\r\n"),
        (ftp_client, ftp_server, f_sport, 21, b"PASS guest@lab.org\r\n"),
    ]
    for step_i, (s_ip, d_ip, sp, dp, payload) in enumerate(f_cmds):
        ftp_pkt = Ether(src=client_mac, dst=server_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=dp, flags="PA") / Raw(load=payload)
        ftp_pkt.time = t_ftp + 0.03 * (step_i + 1)
        packets.append(ftp_pkt)

    # Telnet
    tel_client = "192.168.1.200"
    tel_server = "192.168.1.50"
    t_tel = base_time + 38.0
    tel_sport = 43100
    t_syn = Ether(src=client_mac, dst=server_mac) / IP(src=tel_client, dst=tel_server) / TCP(sport=tel_sport, dport=23, flags="S")
    t_syn.time = t_tel
    packets.append(t_syn)

    tel_dialogue = [
        (tel_server, tel_client, 23, tel_sport, b"\xff\xfd\x18\xff\xfd\x20\r\nlogin: "),
        (tel_client, tel_server, tel_sport, 23, b"admin\r\n"),
        (tel_server, tel_client, 23, tel_sport, b"Password: "),
        (tel_client, tel_server, tel_sport, 23, b"SuperPass!2024\r\n"),
    ]
    for step_i, (s_ip, d_ip, sp, dp, payload) in enumerate(tel_dialogue):
        tel_pkt = Ether(src=client_mac, dst=server_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=dp, flags="PA") / Raw(load=payload)
        tel_pkt.time = t_tel + 0.05 * (step_i + 1)
        packets.append(tel_pkt)

    # Suspicious C2 ports
    suspicious_tests = [
        ("192.168.1.55", "198.51.100.22", 4444, b"\x00\x00\x00\x20metasploit_shell"),
        ("192.168.1.55", "203.0.113.88", 31337, b"*!*PONG*!* BACK_ORIFICE_PING"),
        ("192.168.1.100", "198.51.100.99", 6667, b"NICK bot_4491\r\nUSER bot 0 * :Zombie Bot\r\nJOIN #darkc2\r\n"),
        ("192.168.1.200", "203.0.113.5", 1337, b"ROOTKIT_BEACON_ID=9081726354\r\n"),
    ]
    for idx, (src_h, dst_h, suspicious_p, load_data) in enumerate(suspicious_tests):
        t_susp = base_time + 45.0 + (idx * 2.5)
        sp = 45000 + idx * 37

        p_s = Ether(src=client_mac, dst=gateway_mac) / IP(src=src_h, dst=dst_h) / TCP(sport=sp, dport=suspicious_p, flags="S")
        p_s.time = t_susp
        packets.append(p_s)

        p_sa = Ether(src=gateway_mac, dst=client_mac) / IP(src=dst_h, dst=src_h) / TCP(sport=suspicious_p, dport=sp, flags="SA")
        p_sa.time = t_susp + 0.015
        packets.append(p_sa)

        p_ack = Ether(src=client_mac, dst=gateway_mac) / IP(src=src_h, dst=dst_h) / TCP(sport=sp, dport=suspicious_p, flags="A")
        p_ack.time = t_susp + 0.018
        packets.append(p_ack)

        p_data = Ether(src=client_mac, dst=gateway_mac) / IP(src=src_h, dst=dst_h) / TCP(sport=sp, dport=suspicious_p, flags="PA") / Raw(load=load_data)
        p_data.time = t_susp + 0.02
        packets.append(p_data)

    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)
    print(f"  [+] malware_c2.pcap: {len(packets)} packets ({os.path.getsize(output_path)/1024:.1f} KB)")
    return len(packets)


# ── Scenario 4: Full Attack (all 5 signals) ───────────────────────────────

def create_full_attack_pcap(output_path: str, base_time: float = 1714000000.0):
    """Uses the existing generate_sample.py's create_sample_pcap for the full scenario."""
    from generate_sample import create_sample_pcap
    _, count = create_sample_pcap(output_path, base_time)
    print(f"  [+] full_attack.pcap: {count} packets ({os.path.getsize(output_path)/1024:.1f} KB)")
    return count


# ── Main: generate all scenarios ──────────────────────────────────────────

def generate_all_scenarios(output_dir: str = "scenarios"):
    os.makedirs(output_dir, exist_ok=True)
    base_time = 1714000000.0

    print("[*] Generating threat scenario captures...")
    create_normal_pcap(os.path.join(output_dir, "normal.pcap"), base_time)
    create_port_scan_pcap(os.path.join(output_dir, "port_scan.pcap"), base_time)
    create_malware_c2_pcap(os.path.join(output_dir, "malware_c2.pcap"), base_time)
    create_full_attack_pcap(os.path.join(output_dir, "full_attack.pcap"), base_time)
    print("[+] All 4 scenarios generated successfully.")


if __name__ == "__main__":
    generate_all_scenarios()
