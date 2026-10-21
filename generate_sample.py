#!/usr/bin/env python3
"""
generate_sample.py
------------------
Generates a realistic synthetic network capture (sample.pcap) for information
security lab analysis using Scapy.

Traffic composition (~600 packets spanning ~90 seconds):
1. Normal background traffic:
   - ARP requests and replies
   - UDP DNS queries & responses (port 53)
   - TCP HTTPS sessions (port 443) with SYN, ACK, PSH-ACK, FIN
   - TCP SSH sessions (port 22)
   - ICMP ping traffic
   - Distributed across 8 internal IPs (192.168.1.x) and diverse external hosts.
2. Threat Signals (designed to trigger all 5 detection modules):
   - Signal 1: Staged Port Scan - 192.168.1.99 probes 42 distinct TCP ports on 192.168.1.50 in a 3s window.
   - Signal 2: Plaintext protocols - Unencrypted HTTP (port 80 GET request), FTP (port 21 credentials), Telnet (port 23 login).
   - Signal 3: Suspicious backdoor / C2 ports - Ports 4444 (Metasploit), 31337 (Back Orifice), 6667 (IRC botnet), 1337.
   - Signal 4: Heavy Talker - 192.168.1.105 streams ~150 large MTU-sized packets (>1400 bytes), accounting for >60% of total byte volume.
   - Signal 5: ICMP Flooding / Sweep - 192.168.1.42 transmits 40 ICMP echo requests in rapid succession.
"""

import os
import random
import time

# Disable Scapy verbose logging before importing layers
from scapy.config import conf
conf.verb = 0

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap,
)


def create_sample_pcap(output_path="sample.pcap", base_time=None):
    if base_time is None:
        base_time = 1714000000.0  # Approx Wed Apr 24 2024 23:06:40 UTC

    packets = []

    internal_hosts = [
        "192.168.1.10",
        "192.168.1.25",
        "192.168.1.42",
        "192.168.1.50",
        "192.168.1.55",
        "192.168.1.99",
        "192.168.1.100",
        "192.168.1.105",
        "192.168.1.150",
        "192.168.1.200",
    ]
    gateway_ip = "192.168.1.1"
    gateway_mac = "52:54:00:12:34:56"
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    external_web_ips = ["93.184.216.34", "104.244.42.1", "151.101.1.69", "140.82.112.4"]

    client_mac = "00:50:56:c0:00:08"
    server_mac = "00:50:56:c0:00:01"

    print("[*] Generating synthetic packets...")

    # -------------------------------------------------------------
    # 1. ARP Resolution Packets (t = 0.0s to 5.0s) ~ 16 packets
    # -------------------------------------------------------------
    for i, host in enumerate(internal_hosts[:8]):
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

    # -------------------------------------------------------------
    # 2. Normal DNS Resolutions (t = 2.0s to 85.0s) ~ 48 packets
    # -------------------------------------------------------------
    sample_domains = [
        "api.github.com",
        "cloudflare.com",
        "updates.security.org",
        "cdn.example.net",
        "mail.google.com",
        "pypi.org",
        "aws.amazon.com",
        "microsoft.com",
    ]
    for i, domain in enumerate(sample_domains * 3):
        client = internal_hosts[i % len(internal_hosts)]
        dns_server = dns_servers[i % len(dns_servers)]
        t_req = base_time + 2.0 + (i * 3.5)
        sport = 49152 + (i * 73) % 15000

        p_req = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=dns_server) / UDP(sport=sport, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="A")
        )
        p_req.time = t_req
        packets.append(p_req)

        p_res = Ether(src=gateway_mac, dst=client_mac) / IP(src=dns_server, dst=client) / UDP(sport=53, dport=sport) / DNS(
            qr=1, aa=1, rd=1, qd=DNSQR(qname=domain, qtype="A"), an=DNSRR(rrname=domain, rdata="93.184.216.34", ttl=300)
        )
        p_res.time = t_req + 0.018
        packets.append(p_res)

    # -------------------------------------------------------------
    # 3. Normal HTTPS Traffic (Port 443) (t = 6.0s to 88.0s) ~ 90 packets
    # -------------------------------------------------------------
    for i in range(15):
        client = internal_hosts[(i * 3) % len(internal_hosts)]
        ext_ip = external_web_ips[i % len(external_web_ips)]
        sport = 50000 + i * 117
        t_start = base_time + 6.0 + (i * 5.4)

        # Handshake
        syn = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="S", seq=1000)
        syn.time = t_start
        packets.append(syn)

        synack = Ether(src=gateway_mac, dst=client_mac) / IP(src=ext_ip, dst=client) / TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=1001)
        synack.time = t_start + 0.02
        packets.append(synack)

        ack = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=5001)
        ack.time = t_start + 0.022
        packets.append(ack)

        # TLS Client Hello
        tls_data = b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03" + os.urandom(120)
        data1 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001) / Raw(load=tls_data)
        data1.time = t_start + 0.03
        packets.append(data1)

        # TLS Server Hello + Certificate
        server_tls = b"\x16\x03\x03\x01\x20\x02\x00\x00" + os.urandom(480)
        data2 = Ether(src=gateway_mac, dst=client_mac) / IP(src=ext_ip, dst=client) / TCP(sport=443, dport=sport, flags="PA", seq=5001, ack=1001 + len(tls_data)) / Raw(load=server_tls)
        data2.time = t_start + 0.06
        packets.append(data2)

        ack2 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client, dst=ext_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001 + len(tls_data), ack=5001 + len(server_tls))
        ack2.time = t_start + 0.065
        packets.append(ack2)

    # -------------------------------------------------------------
    # 4. Normal SSH Traffic (Port 22) (t = 12.0s to 45.0s) ~ 15 packets
    # -------------------------------------------------------------
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

    # -------------------------------------------------------------
    # 5. THREAT SIGNAL 1: Staged TCP Port Scan (Severity HIGH)
    # 192.168.1.99 probes 42 distinct destination ports on 192.168.1.50
    # Window: t = 25.0s to 28.5s (~84 packets: SYN + replies)
    # -------------------------------------------------------------
    scanner_ip = "192.168.1.99"
    target_ip = "192.168.1.50"
    scan_ports = [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135,
        139, 143, 389, 443, 445, 465, 587, 636, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
        8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
        50000, 4444, 31337, 1337, 6667, 8081
    ]  # 42 ports >= 15 threshold
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

    # -------------------------------------------------------------
    # 6. THREAT SIGNAL 2: Plaintext / Insecure Protocols (Severity MEDIUM)
    # HTTP port 80 (with GET), FTP port 21, Telnet port 23 (~20 packets)
    # -------------------------------------------------------------
    # A) HTTP on Port 80
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
        b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    p_hreq = Ether(src=client_mac, dst=gateway_mac) / IP(src=http_client, dst=web_server) / TCP(sport=h_sport, dport=80, flags="PA") / Raw(load=http_req)
    p_hreq.time = t_http + 0.02
    packets.append(p_hreq)

    http_res = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: 104\r\n"
        b"Server: Apache/2.4.56\r\n\r\n"
        b"<html><body><h1>Admin Console</h1><p>Unencrypted Session Warning!</p></body></html>"
    )
    p_hres = Ether(src=gateway_mac, dst=client_mac) / IP(src=web_server, dst=http_client) / TCP(sport=80, dport=h_sport, flags="PA") / Raw(load=http_res)
    p_hres.time = t_http + 0.05
    packets.append(p_hres)

    # B) FTP on Port 21
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
        (ftp_server, ftp_client, 21, f_sport, b"331 Guest login ok, send your complete e-mail as password.\r\n"),
        (ftp_client, ftp_server, f_sport, 21, b"PASS guest@infosec-lab.org\r\n"),
        (ftp_server, ftp_client, 21, f_sport, b"230 Anonymous access granted, restrictions apply.\r\n"),
        (ftp_client, ftp_server, f_sport, 21, b"SYST\r\n"),
        (ftp_server, ftp_client, 21, f_sport, b"215 UNIX Type: L8\r\n"),
    ]
    for step_i, (s_ip, d_ip, sp, dp, payload) in enumerate(f_cmds):
        ftp_pkt = Ether(src=client_mac, dst=server_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=dp, flags="PA") / Raw(load=payload)
        ftp_pkt.time = t_ftp + 0.03 * (step_i + 1)
        packets.append(ftp_pkt)

    # C) Telnet on Port 23
    tel_client = "192.168.1.200"
    tel_server = "192.168.1.50"
    t_tel = base_time + 38.0
    tel_sport = 43100

    t_syn = Ether(src=client_mac, dst=server_mac) / IP(src=tel_client, dst=tel_server) / TCP(sport=tel_sport, dport=23, flags="S")
    t_syn.time = t_tel
    packets.append(t_syn)

    tel_dialogue = [
        (tel_server, tel_client, 23, tel_sport, b"\xff\xfd\x18\xff\xfd\x20\r\nDebian GNU/Linux 11\r\nlogin: "),
        (tel_client, tel_server, tel_sport, 23, b"admin\r\n"),
        (tel_server, tel_client, 23, tel_sport, b"Password: "),
        (tel_client, tel_server, tel_sport, 23, b"AdminSuperPass!2024\r\n"),
        (tel_server, tel_client, 23, tel_sport, b"Last login: Wed Apr 24 20:10:01\r\nadmin@legacy-srv:~$ "),
    ]
    for step_i, (s_ip, d_ip, sp, dp, payload) in enumerate(tel_dialogue):
        tel_pkt = Ether(src=client_mac, dst=server_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=dp, flags="PA") / Raw(load=payload)
        tel_pkt.time = t_tel + 0.05 * (step_i + 1)
        packets.append(tel_pkt)

    # -------------------------------------------------------------
    # 7. THREAT SIGNAL 3: Suspicious & Backdoor Ports (Severity MEDIUM)
    # 4444 (Metasploit), 31337 (Back Orifice), 6667 (IRC Botnet), 1337 (Elite)
    # ~16 packets
    # -------------------------------------------------------------
    suspicious_tests = [
        ("192.168.1.55", "198.51.100.22", 4444, b"\x00\x00\x00\x20\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74"),
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

    # -------------------------------------------------------------
    # 8. THREAT SIGNAL 5: ICMP Ping Sweep / Volume (Severity LOW)
    # 192.168.1.42 transmits 40 ICMP echo requests to 192.168.1.1 (~80 packets)
    # -------------------------------------------------------------
    icmp_attacker = "192.168.1.42"
    t_icmp = base_time + 55.0
    for seq_num in range(40):
        t_pkt = t_icmp + seq_num * 0.12
        req = Ether(src=client_mac, dst=gateway_mac) / IP(src=icmp_attacker, dst=gateway_ip) / ICMP(type=8, code=0, id=0x1234, seq=seq_num) / Raw(load=b"SecurityLabPingSweepPayload" * 2)
        req.time = t_pkt
        packets.append(req)

        rep = Ether(src=gateway_mac, dst=client_mac) / IP(src=gateway_ip, dst=icmp_attacker) / ICMP(type=0, code=0, id=0x1234, seq=seq_num) / Raw(load=b"SecurityLabPingSweepPayload" * 2)
        rep.time = t_pkt + 0.003
        packets.append(rep)

    # -------------------------------------------------------------
    # 9. THREAT SIGNAL 4: Heavy Talker (Severity LOW/INFO)
    # 192.168.1.105 sends a large volume of heavy data packets (~1450 bytes)
    # to 104.244.42.1 (~180 packets)
    # -------------------------------------------------------------
    heavy_host = "192.168.1.105"
    heavy_dest = "104.244.42.1"
    t_heavy = base_time + 62.0
    heavy_sport = 58912

    p_h_syn = Ether(src=client_mac, dst=gateway_mac) / IP(src=heavy_host, dst=heavy_dest) / TCP(sport=heavy_sport, dport=443, flags="S")
    p_h_syn.time = t_heavy
    packets.append(p_h_syn)

    p_h_sa = Ether(src=gateway_mac, dst=client_mac) / IP(src=heavy_dest, dst=heavy_host) / TCP(sport=443, dport=heavy_sport, flags="SA")
    p_h_sa.time = t_heavy + 0.015
    packets.append(p_h_sa)

    chunk_payload = b"\x17\x03\x03" + os.urandom(1417)
    for chunk_i in range(145):
        t_chunk = t_heavy + 0.03 + (chunk_i * 0.15)
        p_chunk = Ether(src=client_mac, dst=gateway_mac) / IP(src=heavy_host, dst=heavy_dest) / TCP(sport=heavy_sport, dport=443, flags="PA", seq=1000 + chunk_i * 1420) / Raw(load=chunk_payload)
        p_chunk.time = t_chunk
        packets.append(p_chunk)

        if chunk_i % 4 == 0:
            p_ack = Ether(src=gateway_mac, dst=client_mac) / IP(src=heavy_dest, dst=heavy_host) / TCP(sport=443, dport=heavy_sport, flags="A", ack=1000 + (chunk_i + 1) * 1420)
            p_ack.time = t_chunk + 0.005
            packets.append(p_ack)

    # -------------------------------------------------------------
    # 10. Ambient background traffic to reach ~600 packets over ~90 seconds
    # -------------------------------------------------------------
    for extra_i in range(50):
        t_amb = base_time + 1.0 + (extra_i * 1.76)
        s_ip = internal_hosts[extra_i % len(internal_hosts)]
        d_ip = external_web_ips[extra_i % len(external_web_ips)]
        sp = 51000 + extra_i * 19
        p_amb = Ether(src=client_mac, dst=gateway_mac) / IP(src=s_ip, dst=d_ip) / TCP(sport=sp, dport=443, flags="PA") / Raw(load=os.urandom(random.randint(60, 500)))
        p_amb.time = t_amb
        packets.append(p_amb)

    # Sort all packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    duration = float(packets[-1].time) - float(packets[0].time)
    print(f"[*] Total packets generated: {len(packets)}")
    print(f"[*] Total duration: {duration:.2f} seconds")

    wrpcap(output_path, packets)
    file_size_kb = os.path.getsize(output_path) / 1024.0
    print(f"[+] Successfully wrote {output_path} ({file_size_kb:.2f} KB)")
    return output_path, len(packets)


if __name__ == "__main__":
    create_sample_pcap("sample.pcap")
