from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta
import random
import string

# Config
num_dns = 100
num_http = 100
num_smtp = 50
num_ftp = 50
num_tls = 50
num_internal_tcp = 50
num_filler = 100
total_packets = num_dns + num_http + num_smtp + num_ftp + num_tls + num_internal_tcp + num_filler

# Dummy IPs
internal_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
external_ips = ["8.8.8.8", "93.184.216.34", "1.1.1.1", "142.250.190.78"]

# Initialize time
base_time = datetime.now()
time_increment = timedelta(milliseconds=500)
pkt_time = base_time

# Packet list
packets = []

# Helper to add packet with timestamp
def add_packet(pkt):
    global pkt_time
    pkt.time = pkt_time.timestamp()
    packets.append(pkt)
    pkt_time += time_increment

# DNS packets
domains = ["example.com", "testdomain.org", "mysite.net", "securebank.com", "shoponline.store"]
for _ in range(num_dns):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    domain = random.choice(domains)
    dns_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024,65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    add_packet(dns_pkt)

# HTTP GET/POST packets
for _ in range(num_http):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    method = random.choice(["GET", "POST"])
    uri = f"/api/{random.choice(['data', 'login', 'upload', 'page'])}.html"
    http_payload = (
        f"{method} {uri} HTTP/1.1\r\n"
        f"Host: {random.choice(['www.example.com', 'api.example.net', 'secure.example.org'])}\r\n"
        f"User-Agent: TestAgent\r\n"
        f"Referer: http://referrer.example.com\r\n"
        f"Cookie: sessionid={random.randint(1000,9999)}\r\n"
        f"\r\n"
        f"Email: {random.choice(['alice@example.com','bob@test.com','user@secure.org'])}\n"
        f"MD5: 0123456789abcdef0123456789abcdef\n"
        f"Bitcoin: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT\n"
        f"Phone: +1-555-123-4567\n"
        f"SSN: 123-45-6789\n"
        f"Credit Card: 4111 1111 1111 1111\n"
        f"Base64: SGVsbG8gV29ybGQ=\n"
        f"Malware: powershell\n"
    )
    http_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=80, flags="PA") / Raw(load=http_payload)
    add_packet(http_pkt)

# SMTP packets
for _ in range(num_smtp):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    smtp_payload = (
        f"From: bob@example.com\r\n"
        f"To: charlie@example.net\r\n"
        f"Subject: Test Email {_}\r\n"
        f"\r\n"
        f"This is test email number {_}.\n"
    )
    smtp_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=25, flags="PA") / Raw(load=smtp_payload)
    add_packet(smtp_pkt)

# FTP control packets
for _ in range(num_ftp):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    if _ % 2 == 0:
        ftp_payload = f"USER testuser{_}\r\n"
    else:
        ftp_payload = f"PASS testpassword{_}123\r\n"
    ftp_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=21, flags="PA") / Raw(load=ftp_payload)
    add_packet(ftp_pkt)

# TLS SNI packets
for _ in range(num_tls):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    sni_host = f"secure{_}.example.com"
    tls_payload = b"\x16\x03\x01\x00\x4a\x01\x00\x00\x46\x03\x03" + \
                  b"\x00" * 34 + b"\x00\x00\x00\x17" + \
                  b"\x00\x00" + \
                  b"\x00" + bytes([len(sni_host)]) + sni_host.encode('ascii')
    tls_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=443, flags="PA") / Raw(load=tls_payload)
    add_packet(tls_pkt)

# Internal TCP with file magics
file_magics = [
    b"%PDF-1.4 some pdf content",
    b"\x4D\x5A\x90\x00\x03\x00\x00\x00 exe header...",
    b"PK\x03\x04 zipped content",
    b"DOCX\x00\x00\x00 word content",
    b"\xFF\xD8\xFF jpeg image content"
]
for _ in range(num_internal_tcp):
    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(internal_ips)
    file_payload = random.choice(file_magics)
    file_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=random.randint(1024,65535), flags="PA") / Raw(load=file_payload)
    add_packet(file_pkt)

# Filler traffic (TCP/UDP random)
for _ in range(num_filler):
    src_ip = random.choice(internal_ips + external_ips)
    dst_ip = random.choice(internal_ips + external_ips)
    protocol = random.choice(["TCP", "UDP"])
    rand_text = ''.join(random.choices(string.ascii_letters + string.digits + " ", k=random.randint(20, 100)))
    if protocol == "TCP":
        filler_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024,65535), dport=random.randint(1024,65535), flags="PA") / Raw(load=rand_text.encode('utf-8'))
    else:
        filler_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024,65535), dport=random.randint(1024,65535)) / Raw(load=rand_text.encode('utf-8'))
    add_packet(filler_pkt)

# Save PCAP
pcap_file = "realistic_test_payload_500_packets.pcap"
wrpcap(pcap_file, packets)

print(f"Generated PCAP: {pcap_file} with {len(packets)} packets!")
