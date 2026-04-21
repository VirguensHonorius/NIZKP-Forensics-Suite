import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime
import hashlib
import json
import time
import os
from pathlib import Path
from zk_engine import build_privacy_preserving_proof, parse_connections_scapy

print("LOADING prover.py FROM:", __file__)
# Optional HTTP/DNS layers
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    HTTP_DNS_AVAILABLE = True
except ImportError:
    HTTP_DNS_AVAILABLE = False
    print("⚠ HTTP/DNS layers not available - basic analysis only")


class ProverEngine:
    """Enhanced PCAP analysis engine with strict validation"""

    def __init__(self):
        self.packets = []
        self.connections = []
        self.summary = {}
        self.file_path = None

    def extract_searchable_payload(self, raw_payload, src_port, dst_port, protocol):
        """Extract all possible searchable metadata from payloads - Complete Version"""
        if not raw_payload:
            return "[No payload]"

        searchable_info = []

        try:
            # TLS/SSL Analysis - Extract unencrypted metadata
            if len(raw_payload) >= 6 and raw_payload[0] in [0x16, 0x17, 0x14, 0x15]:
                version_major, version_minor = raw_payload[1], raw_payload[2]
                tls_versions = {(3, 1): "TLS 1.0", (3, 2): "TLS 1.1", (3, 3): "TLS 1.2", (3, 4): "TLS 1.3"}
                version = tls_versions.get((version_major, version_minor), f"TLS {version_major}.{version_minor}")

                # Extract Server Name Indication (SNI) from Client Hello
                if raw_payload[0] == 0x16 and len(raw_payload) > 43:
                    try:
                        # Look for SNI in TLS handshake
                        sni_start = raw_payload.find(b'\x00\x00')
                        if sni_start > 0:
                            for i in range(sni_start, min(len(raw_payload) - 10, sni_start + 200)):
                                if raw_payload[i:i + 2] == b'\x00\x00':
                                    try:
                                        potential_hostname = raw_payload[i + 9:i + 50]
                                        if b'.' in potential_hostname:
                                            hostname = potential_hostname.split(b'\x00')[0]
                                            if len(hostname) > 3 and all(32 <= b <= 126 for b in hostname):
                                                searchable_info.append(f"SNI: {hostname.decode('ascii')}")
                                                break
                                    except:
                                        pass
                        searchable_info.append(f"{version} Handshake")
                    except:
                        searchable_info.append(f"{version} Handshake")
                else:
                    searchable_info.append(f"{version} Data")

            # SSH Analysis - Extract version and algorithms
            elif raw_payload.startswith(b'SSH-'):
                try:
                    lines = raw_payload.split(b'\r\n')
                    ssh_banner = lines[0].decode('ascii')
                    searchable_info.append(f"SSH: {ssh_banner}")

                    # Extract key exchange if present
                    if len(lines) > 1:
                        for line in lines[1:3]:
                            if b'diffie-hellman' in line.lower() or b'ecdh' in line.lower():
                                searchable_info.append(f"KEX: {line.decode('ascii', errors='ignore')[:50]}")
                except:
                    searchable_info.append("SSH Protocol")

            # HTTP Analysis - Extract headers and URLs
            elif any(raw_payload.startswith(method) for method in
                     [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ']):
                try:
                    lines = raw_payload.split(b'\r\n')
                    # Request line
                    request_line = lines[0].decode('ascii')
                    searchable_info.append(f"HTTP: {request_line}")

                    # Extract important headers
                    for line in lines[1:10]:
                        if not line:
                            break
                        header = line.decode('ascii', errors='ignore')
                        if any(header.lower().startswith(h) for h in ['host:', 'user-agent:', 'referer:', 'cookie:']):
                            searchable_info.append(header[:100])
                except:
                    searchable_info.append("HTTP Request")

            # HTTP Response Analysis
            elif raw_payload.startswith(b'HTTP/'):
                try:
                    lines = raw_payload.split(b'\r\n')
                    status_line = lines[0].decode('ascii')
                    searchable_info.append(f"HTTP Response: {status_line}")

                    # Extract server info
                    for line in lines[1:5]:
                        if not line:
                            break
                        header = line.decode('ascii', errors='ignore')
                        if header.lower().startswith('server:'):
                            searchable_info.append(header[:100])
                except:
                    searchable_info.append("HTTP Response")

            # FTP Analysis - Extract commands and responses
            elif any(cmd in raw_payload.upper() for cmd in [b'USER ', b'PASS ', b'RETR ', b'STOR ', b'LIST', b'PWD']):
                try:
                    ftp_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"FTP: {ftp_data[:100]}")
                except:
                    searchable_info.append("FTP Command")

            # SMTP Analysis - Extract commands and email info
            elif any(cmd in raw_payload.upper() for cmd in [b'HELO ', b'EHLO ', b'MAIL FROM:', b'RCPT TO:', b'DATA']):
                try:
                    smtp_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"SMTP: {smtp_data[:100]}")
                except:
                    searchable_info.append("SMTP Command")

            # POP3 Analysis
            elif any(cmd in raw_payload.upper() for cmd in [b'USER ', b'PASS ', b'STAT', b'LIST', b'RETR', b'DELE']):
                try:
                    pop3_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"POP3: {pop3_data[:100]}")
                except:
                    searchable_info.append("POP3 Command")

            # IMAP Analysis
            elif any(cmd in raw_payload.upper() for cmd in [b'LOGIN', b'SELECT', b'FETCH', b'STORE', b'SEARCH']):
                try:
                    imap_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"IMAP: {imap_data[:100]}")
                except:
                    searchable_info.append("IMAP Command")

            # DNS Analysis - Enhanced for proper DNS packet parsing
            elif ((dst_port == 53 or src_port == 53) and protocol == "UDP") or b'\x01\x00\x00\x01' in raw_payload[:20]:
                try:
                    dns_info = []

                    if len(raw_payload) >= 12:
                        transaction_id = int.from_bytes(raw_payload[0:2], 'big')
                        flags = int.from_bytes(raw_payload[2:4], 'big')
                        questions = int.from_bytes(raw_payload[4:6], 'big')
                        answers = int.from_bytes(raw_payload[6:8], 'big')

                        is_response = bool(flags & 0x8000)
                        response_code = flags & 0x000F

                        if is_response:
                            dns_info.append(f"DNS Response (Code: {response_code})")
                        else:
                            dns_info.append("DNS Query")

                        try:
                            pos = 12
                            domains_found = []

                            for _ in range(min(questions, 5)):
                                if pos >= len(raw_payload):
                                    break

                                domain_parts = []
                                while pos < len(raw_payload):
                                    length = raw_payload[pos]
                                    if length == 0:
                                        pos += 1
                                        break
                                    elif length & 0xC0:
                                        pos += 2
                                        break
                                    else:
                                        pos += 1
                                        if pos + length <= len(raw_payload):
                                            part = raw_payload[pos:pos + length].decode('ascii', errors='ignore')
                                            if part and all(c.isalnum() or c in '-.' for c in part):
                                                domain_parts.append(part)
                                            pos += length
                                        else:
                                            break

                                if domain_parts:
                                    domain = '.'.join(domain_parts)
                                    if '.' in domain and len(domain) > 3:
                                        domains_found.append(domain)

                                pos += 4

                            if domains_found:
                                dns_info.append(f"Domains: {', '.join(domains_found[:3])}")

                            if is_response and answers > 0:
                                dns_info.append(f"Answers: {answers}")

                                remaining_data = raw_payload[pos:]
                                ip_pattern = []
                                for i in range(0, min(len(remaining_data) - 4, 100), 1):
                                    if i + 4 <= len(remaining_data):
                                        potential_ip = remaining_data[i:i + 4]
                                        if len(potential_ip) == 4:
                                            ip = '.'.join(str(b) for b in potential_ip)
                                            parts = ip.split('.')
                                            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                                                if not ip.startswith('0.') and not ip.endswith('.0'):
                                                    ip_pattern.append(ip)
                                                    if len(ip_pattern) >= 3:
                                                        break

                                if ip_pattern:
                                    dns_info.append(f"IPs: {', '.join(ip_pattern)}")

                        except Exception:
                            text = raw_payload.decode('ascii', errors='ignore')
                            import re
                            domains = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)
                            if domains:
                                clean_domains = [d[0] for d in domains[:3]]
                                dns_info.append(f"Domains: {', '.join(clean_domains)}")

                    searchable_info.append(" | ".join(dns_info) if dns_info else "DNS Traffic")

                except Exception:
                    searchable_info.append("DNS Traffic (Parse Error)")

            # DNS over HTTPS (DoH) - Port 443 with DNS-like patterns
            elif (dst_port == 443 or src_port == 443) and b'dns' in raw_payload.lower():
                try:
                    searchable_info.append("DNS over HTTPS (DoH)")
                    text = raw_payload.decode('ascii', errors='ignore')
                    import re
                    domains = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)
                    if domains:
                        clean_domains = [d[0] for d in domains[:2]]
                        searchable_info.append(f"DoH Domains: {', '.join(clean_domains)}")
                except:
                    searchable_info.append("DNS over HTTPS (DoH)")

            # DHCP Analysis
            elif any(dhcp in raw_payload.upper() for dhcp in [b'DHCP', b'DISCOVER', b'OFFER', b'REQUEST', b'ACK']):
                try:
                    dhcp_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"DHCP: {dhcp_data[:100]}")
                except:
                    searchable_info.append("DHCP Traffic")

            # SNMP Analysis
            elif b'SNMP' in raw_payload.upper() or dst_port == 161 or src_port == 161:
                try:
                    searchable_info.append("SNMP Protocol")
                    # Try to extract OIDs or community strings
                    text = raw_payload.decode('ascii', errors='ignore')
                    if 'public' in text.lower() or 'private' in text.lower():
                        searchable_info.append("SNMP Community String Detected")
                except:
                    searchable_info.append("SNMP Traffic")

            # IRC Analysis
            elif any(irc in raw_payload.upper() for irc in [b'PRIVMSG', b'JOIN ', b'PART ', b'NICK ', b'USER ']):
                try:
                    irc_data = raw_payload.decode('ascii', errors='ignore').strip()
                    searchable_info.append(f"IRC: {irc_data[:100]}")
                except:
                    searchable_info.append("IRC Command")

            # Binary/Encrypted - Try to extract any readable strings
            else:
                try:
                    # Extract readable strings from binary data
                    readable_strings = []
                    current_string = b""

                    for byte in raw_payload[:200]:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += bytes([byte])
                        else:
                            if len(current_string) >= 4:
                                readable_strings.append(current_string.decode('ascii'))
                            current_string = b""

                    if current_string and len(current_string) >= 4:
                        readable_strings.append(current_string.decode('ascii'))

                    if readable_strings:
                        strings_text = ' | '.join(readable_strings[:3])
                        searchable_info.append(f"Strings: {strings_text[:100]}")

                    # Port-based protocol identification
                    port_protocols = {
                        443: "HTTPS", 22: "SSH", 993: "IMAPS", 995: "POP3S",
                        465: "SMTPS", 587: "SMTP-AUTH", 110: "POP3", 143: "IMAP",
                        21: "FTP", 25: "SMTP", 53: "DNS", 80: "HTTP", 23: "TELNET",
                        69: "TFTP", 161: "SNMP", 194: "IRC", 389: "LDAP", 636: "LDAPS"
                    }

                    identified_proto = port_protocols.get(dst_port) or port_protocols.get(src_port)
                    if identified_proto:
                        searchable_info.append(f"{identified_proto} (Encrypted/Binary)")
                    else:
                        searchable_info.append(f"{protocol} Port {dst_port} (Binary)")

                except:
                    searchable_info.append("[Binary/Encrypted Data]")

            # Return combined searchable information
            return " | ".join(searchable_info) if searchable_info else "[No extractable data]"

        except Exception:
            return "[Parse Error]"

    def import_pcap(self, file_path):
        """Import and analyze PCAP file with enhanced protocol detection and TCP stream reconstruction"""
        self.file_path = file_path
        self.packets = rdpcap(file_path)
        self.connections = []
        times = []

        # TCP stream reconstruction
        tcp_streams = {}  # key: (src_ip, src_port, dst_ip, dst_port), value: payload data

        # First pass: collect TCP streams
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport

                # Create bidirectional stream keys
                stream_key1 = (src_ip, src_port, dst_ip, dst_port)
                stream_key2 = (dst_ip, dst_port, src_ip, src_port)

                # Use the first occurrence as the canonical key
                if stream_key1 not in tcp_streams and stream_key2 not in tcp_streams:
                    tcp_streams[stream_key1] = {'client_data': b'', 'server_data': b'', 'packets': []}

                # Determine which key to use
                active_key = stream_key1 if stream_key1 in tcp_streams else stream_key2

                # Add packet payload to appropriate direction
                if pkt.haslayer('Raw'):
                    payload_data = bytes(pkt['Raw'])
                    tcp_streams[active_key]['packets'].append({
                        'timestamp': float(pkt.time) if hasattr(pkt, 'time') else time.time(),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'data': payload_data,
                        'direction': 'client_to_server' if (src_ip, src_port) == active_key[:2] else 'server_to_client'
                    })

                    # Accumulate data by direction
                    if (src_ip, src_port) == active_key[:2]:
                        tcp_streams[active_key]['client_data'] += payload_data
                    else:
                        tcp_streams[active_key]['server_data'] += payload_data

        # Second pass: create connections with reconstructed payloads
        processed_streams = set()

        for pkt in self.packets:
            proto = None
            src_ip = dst_ip = src_port = dst_port = None
            payload = ""
            packet_time = None

            # Handle IPv4
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Safe timestamp conversion
                try:
                    packet_time = float(pkt.time)
                    times.append(packet_time)
                except (ValueError, TypeError):
                    packet_time = time.time()
                    times.append(packet_time)

                if TCP in pkt:
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    # Check if this is part of a TCP stream we've reconstructed
                    stream_key1 = (src_ip, src_port, dst_ip, dst_port)
                    stream_key2 = (dst_ip, dst_port, src_ip, src_port)

                    active_key = stream_key1 if stream_key1 in tcp_streams else (
                        stream_key2 if stream_key2 in tcp_streams else None)

                    if active_key and active_key not in processed_streams:
                        # Use reconstructed stream data
                        stream_data = tcp_streams[active_key]
                        combined_payload = stream_data['client_data'] + stream_data['server_data']

                        if combined_payload:
                            payload = self.extract_searchable_payload_from_stream(combined_payload, src_port, dst_port,
                                                                                  proto)

                        processed_streams.add(active_key)
                    elif pkt.haslayer('Raw') and active_key in processed_streams:
                        # Skip individual packets if we've already processed the stream
                        continue

                elif UDP in pkt:
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    proto = "ICMP"
                    src_port = dst_port = None

            # Handle IPv6 (without ICMPv6)
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

                try:
                    packet_time = float(pkt.time)
                    times.append(packet_time)
                except (ValueError, TypeError):
                    packet_time = time.time()
                    times.append(packet_time)

                if TCP in pkt:
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

            # For non-TCP or if no stream reconstruction, use original payload extraction
            if src_ip and dst_ip and not payload:
                try:
                    # First check for HTTP/DNS if available
                    if HTTP_DNS_AVAILABLE:
                        if pkt.haslayer(HTTPRequest):
                            method = pkt[HTTPRequest].Method.decode('utf-8', errors='ignore')
                            host = pkt[HTTPRequest].Host.decode('utf-8', errors='ignore') if pkt[
                                HTTPRequest].Host else ""
                            path = pkt[HTTPRequest].Path.decode('utf-8', errors='ignore') if pkt[
                                HTTPRequest].Path else ""
                            payload = f"HTTP {method} {host}{path}"
                            proto = "HTTP"
                        elif pkt.haslayer(HTTPResponse):
                            status = pkt[HTTPResponse].Status_Code.decode('utf-8', errors='ignore') if pkt[
                                HTTPResponse].Status_Code else ""
                            payload = f"HTTP Response {status}"
                            proto = "HTTP"
                        elif pkt.haslayer(DNS):
                            if pkt.haslayer(DNSQR):
                                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore') if pkt[DNSQR].qname else ""
                                payload = f"DNS Query: {qname}"
                                proto = "DNS"
                            elif pkt.haslayer(DNSRR):
                                rdata = str(pkt[DNSRR].rdata) if pkt[DNSRR].rdata else ""
                                payload = f"DNS Answer: {rdata}"
                                proto = "DNS"

                    # If no HTTP/DNS payload found, extract raw payload
                    if not payload and pkt.haslayer('Raw'):
                        raw_payload = bytes(pkt['Raw'])
                        payload = self.extract_searchable_payload(raw_payload, src_port, dst_port, proto)

                    # Rest of the original payload processing logic...
                    if not payload and (src_port or dst_port):
                        well_known_ports = {
                            80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
                            21: "FTP", 22: "SSH/SFTP", 69: "TFTP", 989: "FTPS", 990: "FTPS",
                            25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP-SUB",
                            993: "IMAPS", 995: "POP3S", 53: "DNS", 67: "DHCP", 68: "DHCP",
                            123: "NTP", 161: "SNMP", 162: "SNMP-TRAP", 23: "TELNET", 513: "RLOGIN",
                            514: "RSH", 3389: "RDP", 5900: "VNC", 1433: "MSSQL", 1521: "ORACLE",
                            3306: "MYSQL", 5432: "POSTGRESQL", 194: "IRC", 531: "IRC", 6667: "IRC",
                            5222: "XMPP", 5223: "XMPP-SSL", 79: "FINGER", 113: "IDENT", 135: "RPC",
                            139: "NETBIOS", 445: "SMB", 8000: "HTTP-ALT", 8888: "HTTP-ALT",
                            9000: "HTTP-ALT", 9090: "HTTP-ALT", 1935: "RTMP", 554: "RTSP",
                            5004: "RTP", 5060: "SIP", 5061: "SIPS", 500: "ISAKMP", 1723: "PPTP",
                            1701: "L2TP", 4500: "IPSEC-NAT", 389: "LDAP", 636: "LDAPS",
                            88: "KERBEROS", 464: "KERBEROS-PWD", 515: "LPR", 631: "IPP",
                            2049: "NFS", 111: "PORTMAP", 199: "SNMP-MUX", 1812: "RADIUS",
                            1813: "RADIUS-ACCT", 514: "SYSLOG"
                        }
                        if src_port in well_known_ports:
                            proto = well_known_ports[src_port]
                        elif dst_port in well_known_ports:
                            proto = well_known_ports[dst_port]

                except Exception:
                    pass

            # Add connection if we have valid data
            if src_ip and dst_ip and proto:
                connection = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "timestamp": packet_time,
                    "payload": payload
                }

                # Avoid duplicates for TCP streams
                connection_key = (src_ip, src_port, dst_ip, dst_port, proto)
                if not any(
                        conn["src_ip"] == src_ip and conn["dst_ip"] == dst_ip and
                        conn.get("src_port") == src_port and conn.get("dst_port") == dst_port and
                        conn["protocol"] == proto
                        for conn in self.connections
                ):
                    self.connections.append(connection)

        self.summary = self.generate_summary(times)

    def extract_searchable_payload_from_stream(self, stream_data, src_port, dst_port, protocol):
        """Extract searchable information from reconstructed TCP stream"""
        if not stream_data:
            return "[No payload]"

        try:
            # Try to decode as text first
            text_data = stream_data.decode('utf-8', errors='ignore')

            # For HTTP streams, look for complete requests/responses
            if 'HTTP/' in text_data or any(method in text_data for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                # Extract HTTP components
                lines = text_data.split('\r\n')
                http_info = []

                for line in lines[:20]:  # First 20 lines should contain headers
                    if line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                        http_info.append(f"REQUEST: {line}")
                    elif line.startswith('HTTP/'):
                        http_info.append(f"RESPONSE: {line}")
                    elif line.lower().startswith(
                            ('host:', 'user-agent:', 'cookie:', 'authorization:', 'content-type:')):
                        http_info.append(line[:100])

                # Look for body content (after double CRLF)
                body_start = text_data.find('\r\n\r\n')
                if body_start != -1:
                    body = text_data[body_start + 4:body_start + 1000]  # First 1000 chars of body
                    if body.strip():
                        http_info.append(f"BODY: {body[:200]}...")

                return " | ".join(http_info) if http_info else text_data[:500]

            # For other protocols, use enhanced extraction
            return self.extract_searchable_payload(stream_data, src_port, dst_port, protocol)

        except Exception:
            return self.extract_searchable_payload(stream_data, src_port, dst_port, protocol)
            proto = None
            src_ip = dst_ip = src_port = dst_port = None
            payload = ""
            packet_time = None  # Initialize packet_time variable

            # Handle IPv4
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Safe timestamp conversion
                try:
                    packet_time = float(pkt.time)
                    times.append(packet_time)
                except (ValueError, TypeError):
                    packet_time = time.time()  # Use current time as fallback
                    times.append(packet_time)

                if TCP in pkt:
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    proto = "ICMP"
                    src_port = dst_port = None

            # Handle IPv6 (without ICMPv6)
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

                # Safe timestamp conversion
                try:
                    packet_time = float(pkt.time)
                    times.append(packet_time)
                except (ValueError, TypeError):
                    packet_time = time.time()  # Use current time as fallback
                    times.append(packet_time)

                if TCP in pkt:
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

            # Enhanced payload analysis
            if src_ip and dst_ip:
                try:
                    # First check for HTTP/DNS if available
                    if HTTP_DNS_AVAILABLE:
                        if pkt.haslayer(HTTPRequest):
                            method = pkt[HTTPRequest].Method.decode('utf-8', errors='ignore')
                            host = pkt[HTTPRequest].Host.decode('utf-8', errors='ignore') if pkt[
                                HTTPRequest].Host else ""
                            path = pkt[HTTPRequest].Path.decode('utf-8', errors='ignore') if pkt[
                                HTTPRequest].Path else ""
                            payload = f"HTTP {method} {host}{path}"
                            proto = "HTTP"
                        elif pkt.haslayer(HTTPResponse):
                            status = pkt[HTTPResponse].Status_Code.decode('utf-8', errors='ignore') if pkt[
                                HTTPResponse].Status_Code else ""
                            payload = f"HTTP Response {status}"
                            proto = "HTTP"
                        elif pkt.haslayer(DNS):
                            if pkt.haslayer(DNSQR):
                                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore') if pkt[DNSQR].qname else ""
                                payload = f"DNS Query: {qname}"
                                proto = "DNS"
                            elif pkt.haslayer(DNSRR):
                                rdata = str(pkt[DNSRR].rdata) if pkt[DNSRR].rdata else ""
                                payload = f"DNS Answer: {rdata}"
                                proto = "DNS"

                    # If no HTTP/DNS payload found, extract raw payload from TCP/UDP
                    if not payload and (TCP in pkt or UDP in pkt):
                        if pkt.haslayer('Raw'):
                            raw_payload = bytes(pkt['Raw'])
                            payload = self.extract_searchable_payload(raw_payload, src_port, dst_port, proto)
                            # Try to decode as text
                            try:
                                text_payload = raw_payload.decode('utf-8', errors='ignore')
                                # Clean up the payload - remove non-printable characters except newlines
                                clean_payload = ''.join(char for char in text_payload
                                                        if char.isprintable() or char in '\r\n')
                                if clean_payload.strip():
                                    payload = clean_payload.strip()

                                    # Detect common protocols by payload content
                                    if any(ftp_cmd in payload.upper() for ftp_cmd in
                                           ['USER ', 'PASS ', 'RETR ', 'STOR ', 'LIST', 'PWD', 'CWD', 'QUIT', 'SYST',
                                            'TYPE', 'PASV', 'PORT']):
                                        proto = "FTP"
                                    elif payload.startswith('220 ') or payload.startswith('331 ') or payload.startswith(
                                            '230 '):
                                        proto = "FTP"
                                    elif 'HTTP' in payload:
                                        proto = "HTTP"
                                    elif payload.startswith('SSH-'):
                                        proto = "SSH"
                                    elif 'SMTP' in payload or payload.startswith('220 ') or payload.startswith('HELO'):
                                        proto = "SMTP"
                            except (UnicodeDecodeError, AttributeError):
                                # If can't decode as text, show hex representation of first few bytes
                                hex_payload = raw_payload[:50].hex()
                                if hex_payload:
                                    payload = f"[HEX] {hex_payload}"

                        # If still no payload but we have TCP/UDP ports, try to infer protocol
                        if not payload and (src_port or dst_port):
                            well_known_ports = {
                                # Web protocols
                                80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
                                # File transfer
                                21: "FTP", 22: "SSH/SFTP", 69: "TFTP", 989: "FTPS", 990: "FTPS",
                                # Email protocols
                                25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP-SUB",
                                993: "IMAPS", 995: "POP3S",
                                # DNS and network
                                53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP", 162: "SNMP-TRAP",
                                # Remote access
                                23: "TELNET", 513: "RLOGIN", 514: "RSH", 3389: "RDP", 5900: "VNC",
                                # Database
                                1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL", 5432: "POSTGRESQL",
                                # Messaging and communication
                                194: "IRC", 531: "IRC", 6667: "IRC", 5222: "XMPP", 5223: "XMPP-SSL",
                                # Network services
                                79: "FINGER", 113: "IDENT", 135: "RPC", 139: "NETBIOS", 445: "SMB",
                                # Web services
                                8000: "HTTP-ALT", 8888: "HTTP-ALT", 9000: "HTTP-ALT", 9090: "HTTP-ALT",
                                # Gaming and media
                                1935: "RTMP", 554: "RTSP", 5004: "RTP", 5060: "SIP", 5061: "SIPS",
                                # VPN and tunneling
                                500: "ISAKMP", 1723: "PPTP", 1701: "L2TP", 4500: "IPSEC-NAT",
                                # Directory services
                                389: "LDAP", 636: "LDAPS", 88: "KERBEROS", 464: "KERBEROS-PWD",
                                # Print and file sharing
                                515: "LPR", 631: "IPP", 2049: "NFS", 111: "PORTMAP",
                                # Monitoring and management
                                199: "SNMP-MUX", 1812: "RADIUS", 1813: "RADIUS-ACCT", 514: "SYSLOG"
                            }
                            if src_port in well_known_ports:
                                proto = well_known_ports[src_port]
                            elif dst_port in well_known_ports:
                                proto = well_known_ports[dst_port]

                    # Enhanced protocol detection from payload content
                    if payload and proto not in ["HTTP", "DNS", "FTP"]:  # Don't override already detected protocols
                        payload_upper = payload.upper()

                        # Email protocols
                        if any(cmd in payload_upper for cmd in
                               ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT']):
                            proto = "SMTP"
                        elif any(cmd in payload_upper for cmd in ['USER ', 'PASS ', 'STAT', 'LIST', 'RETR', 'DELE']):
                            if 'FTP' not in proto:  # Don't override FTP
                                proto = "POP3"
                        elif any(cmd in payload_upper for cmd in ['LOGIN', 'SELECT', 'FETCH', 'STORE', 'SEARCH']):
                            proto = "IMAP"

                        # Remote access protocols
                        elif payload.startswith('SSH-'):
                            proto = "SSH"
                        elif any(cmd in payload_upper for cmd in ['WILL ', 'WONT ', 'DO ', 'DONT ']):
                            proto = "TELNET"

                        # Database protocols
                        elif any(db in payload_upper for db in
                                 ['SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'CREATE ', 'DROP ']):
                            proto = "SQL"
                        elif 'MYSQL' in payload_upper:
                            proto = "MYSQL"
                        elif 'ORACLE' in payload_upper:
                            proto = "ORACLE"

                        # Network protocols
                        elif any(dhcp in payload_upper for dhcp in ['DHCP', 'DISCOVER', 'OFFER', 'REQUEST', 'ACK']):
                            proto = "DHCP"
                        elif 'SNMP' in payload_upper:
                            proto = "SNMP"

                        # Messaging protocols
                        elif any(irc in payload_upper for irc in ['PRIVMSG', 'JOIN ', 'PART ', 'NICK ', 'USER ']):
                            proto = "IRC"
                        elif any(sip in payload_upper for sip in ['INVITE', 'BYE', 'REGISTER', 'OPTIONS']):
                            proto = "SIP"

                        # File sharing
                        elif any(smb in payload_upper for smb in ['SMB', 'CIFS']):
                            proto = "SMB"
                        elif 'NFS' in payload_upper:
                            proto = "NFS"

                        # Security protocols
                        elif any(ldap in payload_upper for ldap in ['BIND', 'SEARCH', 'ADD', 'DELETE', 'MODIFY']):
                            proto = "LDAP"
                        elif 'KERBEROS' in payload_upper:
                            proto = "KERBEROS"

                except Exception:
                    # If payload parsing fails, continue with basic info
                    pass

            # Add connection if we have valid data
            if src_ip and dst_ip and proto:
                # Use the safely converted timestamp
                connection = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "timestamp": packet_time,
                    "payload": payload
                }
                self.connections.append(connection)

        self.summary = self.generate_summary(times)

    def generate_summary(self, times):
        """Generate comprehensive summary statistics"""
        src_ips = Counter([conn["src_ip"] for conn in self.connections])
        dst_ips = Counter([conn["dst_ip"] for conn in self.connections])
        protocols = Counter([conn["protocol"] for conn in self.connections])

        summary = {
            "total_packets": len(self.packets),
            "total_connections": len(self.connections),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "top_src_ips": src_ips.most_common(5),
            "top_dst_ips": dst_ips.most_common(5),
            "protocols": dict(protocols),
        }

        if times:
            try:
                min_time = min(times)
                max_time = max(times)
                summary["start_time"] = datetime.fromtimestamp(min_time).isoformat()
                summary["end_time"] = datetime.fromtimestamp(max_time).isoformat()
                summary["duration_seconds"] = max_time - min_time
            except (ValueError, TypeError, OSError):
                summary["start_time"] = "Invalid timestamp"
                summary["end_time"] = "Invalid timestamp"
                summary["duration_seconds"] = 0

        return summary


class ProverScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#36393f")
        self.engine = ProverEngine()
        self.summary_labels = {}
        self.expiration_var = tk.BooleanVar()
        self.days_var = tk.StringVar()
        self.entire_pcap_var = tk.BooleanVar()
        self.create_widgets()

    def create_widgets(self):
        """Create all GUI widgets"""
        # Import section
        import_frame = tk.Frame(self, bg="#36393f")
        import_frame.pack(pady=10)

        self.import_btn = tk.Button(import_frame, text="📂 Import PCAP", command=self.load_pcap,
                                    bg="#6366F1", fg="white", font=("Arial", 12))
        self.import_btn.pack(side="left", padx=5)

        self.file_label = tk.Label(import_frame, text="No file loaded",
                                   bg="#36393f", fg="#b9bbbe", font=("Arial", 10))
        self.file_label.pack(side="left", padx=10)

        # Summary section
        self.summary_frame = tk.LabelFrame(self, text="PCAP Summary", bg="#40444b",
                                           font=("Arial", 12, "bold"), fg="#ffffff",
                                           padx=10, pady=10)
        self.summary_frame.pack(padx=20, pady=10, fill="x")

        # Connection filter frame - MOVED HERE so it's always available
        filter_frame = tk.LabelFrame(self, text="🔍 Search Connections",
                                     bg="#40444b", fg="#ffffff", padx=10, pady=10,
                                     font=("Arial", 12, "bold"))
        filter_frame.pack(fill="x", padx=20, pady=10)

        # Search fields - First row
        tk.Label(filter_frame, text="Source IP:", bg="#40444b", fg="#b9bbbe").grid(row=0, column=0, sticky="e", padx=2)
        self.src_ip_entry = tk.Entry(filter_frame, width=15)
        self.src_ip_entry.grid(row=0, column=1, padx=5)

        tk.Label(filter_frame, text="Src Port:", bg="#40444b", fg="#b9bbbe").grid(row=0, column=2, sticky="e", padx=2)
        self.src_port_entry = tk.Entry(filter_frame, width=8)
        self.src_port_entry.grid(row=0, column=3, padx=5)

        tk.Label(filter_frame, text="Destination IP:", bg="#40444b", fg="#b9bbbe").grid(row=0, column=4, sticky="e",
                                                                                        padx=2)
        self.dst_ip_entry = tk.Entry(filter_frame, width=15)
        self.dst_ip_entry.grid(row=0, column=5, padx=5)

        tk.Label(filter_frame, text="Dst Port:", bg="#40444b", fg="#b9bbbe").grid(row=0, column=6, sticky="e", padx=2)
        self.dst_port_entry = tk.Entry(filter_frame, width=8)
        self.dst_port_entry.grid(row=0, column=7, padx=5)

        # Search fields - Second row
        tk.Label(filter_frame, text="Protocol:", bg="#40444b", fg="#b9bbbe").grid(row=1, column=0, sticky="e", padx=2)
        self.proto_entry = tk.Entry(filter_frame, width=15)
        self.proto_entry.grid(row=1, column=1, padx=5)

        tk.Label(filter_frame, text="Payload Keyword:", bg="#40444b", fg="#b9bbbe").grid(row=1, column=2, sticky="e",
                                                                                         padx=2)
        self.keyword_entry = tk.Entry(filter_frame, width=20)
        self.keyword_entry.grid(row=1, column=3, columnspan=2, padx=5, sticky="w")

        # Clear button
        clear_btn = tk.Button(filter_frame, text="🗑️ Clear", command=self.clear_filters,
                              bg="#EF4444", fg="white", font=("Arial", 9))
        clear_btn.grid(row=1, column=5, padx=5)

        # Search button
        self.search_btn = tk.Button(filter_frame, text="🔍 Search Connections",
                                    command=self.filter_connections,
                                    bg="#10B981", fg="white", font=("Arial", 10))
        self.search_btn.grid(row=2, column=0, columnspan=8, pady=10)
        self.search_result_label = tk.Label(filter_frame,
                                            text="Import a PCAP file to start searching connections.",
                                            bg="#40444b", fg="#b9bbbe",
                                            font=("Arial", 9, "italic"))
        self.search_result_label.grid(row=3, column=0, columnspan=8, sticky="w", pady=(5, 0))

        # Results section with dual panes - MOVED HERE so it's always available
        results_frame = tk.Frame(self, bg="#36393f")
        results_frame.pack(fill="both", expand=True, padx=20, pady=5)

        # Left pane - Connection table
        left_frame = tk.LabelFrame(results_frame, text="🔗 Network Connections",
                                   bg="#40444b", fg="#ffffff", font=("Arial", 11, "bold"))
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Connection table with scrollbars
        table_container = tk.Frame(left_frame, bg="#40444b")
        table_container.pack(fill="both", expand=True, padx=10, pady=10)

        v_scrollbar = ttk.Scrollbar(table_container, orient="vertical")
        h_scrollbar = ttk.Scrollbar(table_container, orient="horizontal")

        self.result_table = ttk.Treeview(table_container,
                                         columns=("src", "dst", "proto", "sport", "dport", "timestamp"),
                                         show="headings",
                                         yscrollcommand=v_scrollbar.set,
                                         xscrollcommand=h_scrollbar.set)

        # Configure scrollbars
        v_scrollbar.config(command=self.result_table.yview)
        h_scrollbar.config(command=self.result_table.xview)

        # Column headers and widths for connection table
        columns_config = {
            "src": ("Source IP", 120),
            "dst": ("Destination IP", 120),
            "proto": ("Protocol", 80),
            "sport": ("Src Port", 80),
            "dport": ("Dst Port", 80),
            "timestamp": ("Timestamp", 150)
        }

        for col, (heading, width) in columns_config.items():
            self.result_table.heading(col, text=heading)
            self.result_table.column(col, width=width, anchor="center")

        # Pack connection table and scrollbars
        self.result_table.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        # Right pane - Payload analysis
        right_frame = tk.LabelFrame(results_frame, text="🔍 Payload Analysis",
                                    bg="#40444b", fg="#ffffff", font=("Arial", 11, "bold"))
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))

        # Payload analysis tree
        payload_container = tk.Frame(right_frame, bg="#40444b")
        payload_container.pack(fill="both", expand=True, padx=10, pady=10)

        payload_scrollbar = ttk.Scrollbar(payload_container, orient="vertical")
        self.payload_tree = ttk.Treeview(payload_container,
                                         yscrollcommand=payload_scrollbar.set,
                                         show="tree")
        payload_scrollbar.config(command=self.payload_tree.yview)

        self.payload_tree.grid(row=0, column=0, sticky="nsew")
        payload_scrollbar.grid(row=0, column=1, sticky="ns")

        payload_container.grid_rowconfigure(0, weight=1)
        payload_container.grid_columnconfigure(0, weight=1)

        # Configure tree styles
        style = ttk.Style()
        style.configure("Treeview", background="#2f3136", foreground="#ffffff",
                        fieldbackground="#2f3136", borderwidth=0)
        style.configure("Treeview.Heading", background="#40444b", foreground="#ffffff")

        # Bind selection events
        self.result_table.bind("<<TreeviewSelect>>", self.on_connection_select)
        self.result_table.bind("<<TreeviewSelect>>", self.enable_proof_button, add="+")

        # Proof generation section
        self.proof_frame = tk.Frame(self, bg="#36393f")
        self.proof_frame.pack(pady=10)

        tk.Label(self.proof_frame, text="🔐 Enter Password:", bg="#36393f", fg="#ffffff",
                 font=("Arial", 10, "bold")).pack(side="left")
        self.password_entry = tk.Entry(self.proof_frame, show="*", width=20, font=("Arial", 10))
        self.password_entry.pack(side="left", padx=5)

        tk.Label(self.proof_frame, text="Confirm:", bg="#36393f", fg="#ffffff",
                 font=("Arial", 10, "bold")).pack(side="left")
        self.confirm_password_entry = tk.Entry(self.proof_frame, show="*", width=20, font=("Arial", 10))
        self.confirm_password_entry.pack(side="left", padx=5)
        tk.Checkbutton(self.proof_frame, text="Expire in", variable=self.expiration_var,
                       bg="#36393f", fg="#ffffff", selectcolor="#40444b").pack(side="left", padx=(10, 2))
        tk.Entry(self.proof_frame, textvariable=self.days_var, width=5, font=("Arial", 10)).pack(side="left")
        tk.Label(self.proof_frame, text="days", bg="#36393f", fg="#ffffff",
                 font=("Arial", 10)).pack(side="left", padx=(2, 5))
        tk.Checkbutton(self.proof_frame, text="Prove entire PCAP", variable=self.entire_pcap_var,
                       bg="#36393f", fg="#ffffff", selectcolor="#40444b",
                       command=self.on_checkbox_change).pack(side="left", padx=(10, 5))

        self.generate_btn = tk.Button(self.proof_frame, text="Generate Proof",
                                      command=self.generate_proof,
                                      bg="#EF4444", fg="white", font=("Arial", 10),
                                      state="disabled")
        self.generate_btn.pack(side="left", padx=5)

    def load_pcap(self):
        """Load and analyze PCAP file"""
        file_path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcap *.pcapng *.cap"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        # Validate file extension
        valid_extensions = ('.pcap', '.pcapng', '.cap')
        if not file_path.lower().endswith(valid_extensions):
            messagebox.showerror("Invalid File",
                                 f"Please select a valid PCAP file ({', '.join(valid_extensions)})")
            return

        try:
            # Show loading message and disable import button
            self.file_label.config(text="⏳ Loading and analyzing PCAP...")
            self.import_btn.config(state="disabled")
            self.update()

            # Import and analyze
            self.engine.import_pcap(file_path)

            # Update UI
            filename = os.path.basename(file_path)
            self.file_label.config(text=f"✅ Loaded: {filename}")

            # Display results
            self.display_summary()

            # Update search instruction
            self.search_result_label.config(
                text="PCAP loaded successfully. Use search filters above to find connections.")

            # Re-enable import button
            self.import_btn.config(state="normal")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import PCAP file:\n{str(e)}")
            self.file_label.config(text="❌ Import failed")
            # Re-enable import button
            self.import_btn.config(state="normal")

    def display_summary(self):
        """Display PCAP summary information"""
        # Clear previous summary
        for widget in self.summary_frame.winfo_children():
            widget.destroy()

        summary = self.engine.summary

        # Create summary grid
        summary_grid = tk.Frame(self.summary_frame, bg="#40444b")
        summary_grid.pack(fill="x", pady=5)

        # Summary items
        summary_items = [
            ("Total Packets:", summary.get("total_packets", 0)),
            ("Total Connections:", summary.get("total_connections", 0)),
            ("Unique Source IPs:", summary.get("unique_src_ips", 0)),
            ("Unique Destination IPs:", summary.get("unique_dst_ips", 0)),
            ("Duration:", f"{summary.get('duration_seconds', 0):.1f} seconds"),
            ("Start Time:", summary.get("start_time", "Unknown")),
        ]

        for i, (label, value) in enumerate(summary_items):
            row = i // 2
            col = (i % 2) * 2

            tk.Label(summary_grid, text=label, bg="#40444b", fg="#b9bbbe",
                     font=("Arial", 10, "bold")).grid(row=row, column=col, sticky="e", padx=(0, 5), pady=2)
            tk.Label(summary_grid, text=str(value), bg="#40444b", fg="#ffffff",
                     font=("Arial", 10)).grid(row=row, column=col + 1, sticky="w", padx=(0, 20), pady=2)

        # Protocol distribution
        protocols = summary.get("protocols", {})
        if protocols:
            proto_frame = tk.Frame(self.summary_frame, bg="#40444b")
            proto_frame.pack(fill="x", pady=(10, 0))

            tk.Label(proto_frame, text="Protocol Distribution:", bg="#40444b", fg="#ffffff",
                     font=("Arial", 11, "bold")).pack(anchor="w")

            proto_text = ", ".join([f"{proto}: {count}" for proto, count in protocols.items()])
            tk.Label(proto_frame, text=proto_text, bg="#40444b", fg="#b9bbbe",
                     font=("Arial", 9), wraplength=800).pack(anchor="w", pady=(2, 0))

    def filter_connections(self):
        """Filter and display connections based on search criteria"""
        # Check if PCAP is loaded
        if not self.engine.connections:
            messagebox.showwarning("No Data", "Please import a PCAP file first.")
            return

        self.result_table.delete(*self.result_table.get_children())

        search_criteria = {
            "src_ip": self.src_ip_entry.get().strip(),
            "src_port": self.src_port_entry.get().strip(),
            "dst_ip": self.dst_ip_entry.get().strip(),
            "dst_port": self.dst_port_entry.get().strip(),
            "protocol": self.proto_entry.get().strip().upper(),
            "keyword": self.keyword_entry.get().strip().lower()
        }

        matches_found = 0
        for conn in self.engine.connections:
            # Apply filters with flexible matching
            if search_criteria["src_ip"] and search_criteria["src_ip"] not in str(conn["src_ip"]):
                continue
            if search_criteria["dst_ip"] and search_criteria["dst_ip"] not in str(conn["dst_ip"]):
                continue

            # Port filtering with validation
            if search_criteria["src_port"]:
                try:
                    search_src_port = int(search_criteria["src_port"])
                    if not (0 <= search_src_port <= 65535):
                        messagebox.showerror("Invalid Port", "Source port must be between 0 and 65535")
                        return
                    if conn.get("src_port") != search_src_port:
                        continue
                except ValueError:
                    messagebox.showerror("Invalid Port", "Source port must be a valid number")
                    return

            if search_criteria["dst_port"]:
                try:
                    search_dst_port = int(search_criteria["dst_port"])
                    if not (0 <= search_dst_port <= 65535):
                        messagebox.showerror("Invalid Port", "Destination port must be between 0 and 65535")
                        return
                    if conn.get("dst_port") != search_dst_port:
                        continue
                except ValueError:
                    messagebox.showerror("Invalid Port", "Destination port must be a valid number")
                    return

            # Protocol filtering - allow partial matching
            if search_criteria["protocol"]:
                conn_proto = str(conn["protocol"]).upper()
                if search_criteria["protocol"] not in conn_proto:
                    continue

            # Enhanced keyword search - search in payload with case-insensitive matching
            if search_criteria["keyword"]:
                payload_text = str(conn.get("payload", "")).lower()
                if search_criteria["keyword"] not in payload_text:
                    continue

            # Format timestamp
            try:
                if conn["timestamp"] and conn["timestamp"] > 0:
                    timestamp_str = datetime.fromtimestamp(conn["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp_str = "No timestamp"
            except (ValueError, TypeError, OSError):
                timestamp_str = "Invalid timestamp"

            # Truncate payload for display but keep full text for search
            display_payload = str(conn.get("payload", ""))
            if not display_payload.strip():
                display_payload = "[No payload]"
            elif len(display_payload) > 100:
                display_payload = display_payload[:97] + "..."

            # Insert into table (removed payload column)
            self.result_table.insert("", "end", values=(
                conn["src_ip"],
                conn["dst_ip"],
                conn["protocol"],
                conn.get("src_port", ""),
                conn.get("dst_port", ""),
                timestamp_str
            ))
            matches_found += 1

        # Update the search button text to show results count
        if hasattr(self, 'search_btn'):
            if matches_found > 0:
                self.search_btn.config(text=f"🔍 Found {matches_found} matches")
                self.search_result_label.config(text=f"Showing {matches_found} matching connections.")
            else:
                self.search_btn.config(text="🔍 No matches found")
                self.search_result_label.config(text="No matching connections found.")

        # Auto-reset button text after 3 seconds
        self.after(3000,
                   lambda: self.search_btn.config(text="🔍 Search Connections") if hasattr(self, 'search_btn') else None)

    def on_connection_select(self, event):
        """Handle connection selection and analyze payload"""
        selected = self.result_table.focus()
        if not selected:
            # Clear payload analysis
            for item in self.payload_tree.get_children():
                self.payload_tree.delete(item)
            no_selection = self.payload_tree.insert("", "end", text="📭 No Connection Selected", open=True)
            self.payload_tree.insert(no_selection, "end", text="Select a connection to analyze its payload")
            return

        # Get selected connection data
        values = self.result_table.item(selected)["values"]
        if not values or len(values) < 6:
            return

        # Find the full connection data by matching all fields
        src_ip, dst_ip, protocol = values[0], values[1], values[2]
        src_port, dst_port = str(values[3]), str(values[4])

        # Find matching connection in engine data
        matching_conn = None
        for conn in self.engine.connections:  # Fixed: back to self.engine.connections
            if (str(conn["src_ip"]) == str(src_ip) and
                    str(conn["dst_ip"]) == str(dst_ip) and
                    str(conn["protocol"]) == str(protocol) and
                    str(conn.get("src_port", "")) == str(src_port) and
                    str(conn.get("dst_port", "")) == str(dst_port)):
                matching_conn = conn
                break

        if matching_conn:
            payload = matching_conn.get("payload", "")
            print(f"DEBUG: Found matching connection with payload: {payload[:100]}...")  # Debug output
            self.analyze_payload(payload)
        else:
            print(f"DEBUG: No matching connection found for {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
            print(f"DEBUG: Available connections: {len(self.engine.connections)}")
            for i, conn in enumerate(self.engine.connections[:3]):  # Show first 3 for debugging
                print(
                    f"  Connection {i}: {conn['src_ip']}:{conn.get('src_port')} -> {conn['dst_ip']}:{conn.get('dst_port')} ({conn['protocol']})")

            # Clear payload analysis
            for item in self.payload_tree.get_children():
                self.payload_tree.delete(item)
            no_match = self.payload_tree.insert("", "end", text="⚠️ Connection Data Not Found", open=True)
            self.payload_tree.insert(no_match, "end", text="Could not locate detailed connection data")

    def analyze_payload(self, payload):
        """Analyze payload and categorize findings"""
        # Clear previous analysis
        for item in self.payload_tree.get_children():
            self.payload_tree.delete(item)

        if not payload or payload in ["[No payload]", "[Parse Error]"]:
            no_data = self.payload_tree.insert("", "end", text="📭 No Payload Data", open=True)
            self.payload_tree.insert(no_data, "end", text="No analyzable payload content found")
            return

        # Initialize categories
        categories = {
            "📧 Communication": [],
            "💰 Financial": [],
            "🔐 Security": [],
            "🌐 Network": [],
            "📁 Files": [],
            "🔑 Credentials": [],
            "⚠️ Suspicious": []
        }

        payload_lower = payload.lower()
        payload_text = str(payload)

        # Email and communication patterns
        import re

        # Email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', payload_text)
        for email in emails[:5]:  # Limit to 5
            categories["📧 Communication"].append(f"EMAIL_ADDR: {email}")

        # Domains and hosts
        domains = re.findall(r'(?:host:|domain:|server:)\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload_text, re.IGNORECASE)
        for domain in domains[:5]:
            categories["📧 Communication"].append(f"DOMAIN: {domain}")

        # HTTP hosts
        http_hosts = re.findall(r'host:\s*([a-zA-Z0-9.-]+)', payload_text, re.IGNORECASE)
        for host in http_hosts[:3]:
            categories["🌐 Network"].append(f"HTTP_HOST: {host}")

        # Cookies
        cookies = re.findall(r'cookie:\s*([^;\r\n]+)', payload_text, re.IGNORECASE)
        for cookie in cookies[:3]:
            categories["📧 Communication"].append(f"COOKIE: {cookie[:50]}...")

        # Financial patterns
        # Credit card numbers (basic pattern)
        credit_cards = re.findall(
            r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            payload_text)
        for cc in credit_cards:
            masked = cc[:4] + "****" + cc[-4:] if len(cc) >= 8 else cc
            categories["💰 Financial"].append(f"CREDIT_CARD: {masked}")

        # Bitcoin addresses
        bitcoin = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', payload_text)
        for btc in bitcoin[:3]:
            categories["💰 Financial"].append(f"BITCOIN: {btc}")

        # SSN pattern
        ssn = re.findall(r'\b\d{3}-\d{2}-\d{4}\b', payload_text)
        for s in ssn[:2]:
            categories["💰 Financial"].append(f"SSN: {s}")

        # Security indicators
        # Hash patterns
        md5_hashes = re.findall(r'\b[a-f0-9]{32}\b', payload_lower)
        for hash_val in md5_hashes[:3]:
            categories["🔐 Security"].append(f"HASH_MD5: {hash_val}")

        sha1_hashes = re.findall(r'\b[a-f0-9]{40}\b', payload_lower)
        for hash_val in sha1_hashes[:3]:
            categories["🔐 Security"].append(f"HASH_SHA1: {hash_val[:16]}...")

        # Malware indicators
        malware_indicators = ['powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript']
        for indicator in malware_indicators:
            if indicator in payload_lower:
                categories["⚠️ Suspicious"].append(f"MALWARE_SIG: {indicator}")

        # Credentials
        if 'password' in payload_lower or 'passwd' in payload_lower:
            password_matches = re.findall(r'(?:password|passwd)[:=]\s*([^\s\r\n]+)', payload_text, re.IGNORECASE)
            for pwd in password_matches[:2]:
                categories["🔑 Credentials"].append(f"PASSWORD: {pwd[:8]}...")

        if 'username' in payload_lower or 'user' in payload_lower:
            user_matches = re.findall(r'(?:username|user)[:=]\s*([^\s\r\n]+)', payload_text, re.IGNORECASE)
            for user in user_matches[:2]:
                categories["🔑 Credentials"].append(f"USERNAME: {user}")

        # File paths
        file_paths = re.findall(r'[A-Za-z]:\\[^<>:"|?*\r\n]+', payload_text)
        for path in file_paths[:3]:
            categories["📁 Files"].append(f"WINDOWS_PATH: {path}")

        unix_paths = re.findall(r'/[a-zA-Z0-9._/-]+', payload_text)
        for path in unix_paths[:3]:
            if len(path) > 5:  # Filter out short matches
                categories["📁 Files"].append(f"UNIX_PATH: {path}")

        # Network indicators
        # IP addresses
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', payload_text)
        for ip in ips[:5]:
            # Skip common local IPs to reduce noise
            if not ip.startswith(('127.', '192.168.', '10.', '172.')):
                categories["🌐 Network"].append(f"IP_ADDR: {ip}")

        # URLs
        urls = re.findall(r'https?://[^\s<>"]+', payload_text)
        for url in urls[:3]:
            categories["🌐 Network"].append(f"URL: {url[:50]}...")

        # Suspicious patterns
        # Base64 (long strings)
        base64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', payload_text)
        for b64 in base64_pattern[:2]:
            if len(b64) > 20:
                categories["⚠️ Suspicious"].append(f"BASE64: {b64[:20]}...")

        # SQL injection patterns
        sql_keywords = ['union select', 'drop table', 'insert into', '1=1', "' or '"]
        for keyword in sql_keywords:
            if keyword in payload_lower:
                categories["⚠️ Suspicious"].append(f"SQL_INJECTION: {keyword}")

        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onclick=']
        for pattern in xss_patterns:
            if pattern in payload_lower:
                categories["⚠️ Suspicious"].append(f"XSS_PATTERN: {pattern}")

        # Populate the tree
        for category, items in categories.items():
            if items:
                # Add category with count
                category_node = self.payload_tree.insert("", "end",
                                                         text=f"{category} ({len(items)} items)",
                                                         open=True)
                # Add items
                for item in items:
                    self.payload_tree.insert(category_node, "end", text=f"  ├── {item}")

        # If no categories have data, show a message
        if not any(categories.values()):
            no_findings = self.payload_tree.insert("", "end", text="📋 Raw Payload", open=True)
            # Show first 200 characters of payload
            preview = payload_text[:200] + "..." if len(payload_text) > 200 else payload_text
            self.payload_tree.insert(no_findings, "end", text=f"  └── {preview}")

    def clear_filters(self):
        """Clear all search filters"""
        self.src_ip_entry.delete(0, tk.END)
        self.src_port_entry.delete(0, tk.END)
        self.dst_ip_entry.delete(0, tk.END)
        self.dst_port_entry.delete(0, tk.END)
        self.proto_entry.delete(0, tk.END)
        self.keyword_entry.delete(0, tk.END)

        # Clear the results table
        self.result_table.delete(*self.result_table.get_children())

        # Reset search button text
        if hasattr(self, 'search_btn'):
            self.search_btn.config(text="🔍 Search Connections")

        # Reset search result label
        if self.engine.connections:
            self.search_result_label.config(text="Filters cleared. Use search filters above to find connections.")
        else:
            self.search_result_label.config(text="Import a PCAP file to start searching connections.")

        # Disable proof generation button when clearing (unless entire PCAP is checked)
        if hasattr(self, 'generate_btn') and not self.entire_pcap_var.get():
            self.generate_btn.config(state="disabled")

    def enable_proof_button(self, event):
        """Enable proof generation button when connection is selected OR entire PCAP is checked"""
        if self.result_table.focus() or self.entire_pcap_var.get():
            self.generate_btn.config(state="normal")

    def on_checkbox_change(self):
        """Handle checkbox state changes to enable/disable generate button"""
        if self.entire_pcap_var.get():
            # Entire PCAP checked - enable button regardless of selection
            self.generate_btn.config(state="normal")
        else:
            # Entire PCAP unchecked - only enable if connection is selected
            if self.result_table.focus():
                self.generate_btn.config(state="normal")
            else:
                self.generate_btn.config(state="disabled")

    def generate_proof(self):
        from zk_engine import build_privacy_preserving_proof

        # Check if PCAP is loaded
        if not self.engine.connections:
            messagebox.showwarning("No Data", "Please import a PCAP file first.")
            return

        # Check if entire PCAP mode or if a connection is selected
        if not self.entire_pcap_var.get():
            # Single connection mode - selection required
            selected = self.result_table.focus()
            if not selected:
                messagebox.showwarning("No Selection", "Please select a connection first.")
                return

            values = self.result_table.item(selected)["values"]
            if not values or len(values) < 7:
                messagebox.showerror("Invalid Selection", "Selected connection data is incomplete.")
                return
        else:
            # Entire PCAP mode - no selection needed
            values = None  # We'll handle this case differently

        # Password validation (same for both modes)
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Password Error", "Password must be at least 8 characters long.")
            return

        if not password.strip():
            messagebox.showerror("Password Error", "Password cannot be empty or just spaces.")
            return

        if password != confirm_password:
            messagebox.showerror("Password Error", "Passwords do not match.")
            return

        # Expiration validation (same for both modes)
        expiration_days = None
        if self.expiration_var.get():
            days_input = self.days_var.get().strip()
            if not days_input.isdigit() or int(days_input) <= 0:
                messagebox.showerror("Invalid Days", "Enter a valid number of days (greater than 0)")
                return
            expiration_days = int(days_input)

        # Save path selection
        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Proof Files", "*.json")],
            title="Save Proof As"
        )

        if not save_path:
            return  # user canceled

        if not save_path.lower().endswith('.json'):
            save_path += '.json'

        try:
            # Determine proof scope and selected connection
            if self.entire_pcap_var.get():
                # Entire PCAP mode
                connections_to_prove = []
                for conn in self.engine.connections:
                    conn_string = f"{conn['src_ip']}:{conn.get('src_port', '')}->{conn['dst_ip']}:{conn.get('dst_port', '')} ({conn['protocol']})"
                    connections_to_prove.append(conn_string)

                # For signature, use a hash of the entire PCAP or first connection
                if connections_to_prove:
                    selected_connection_string = "ENTIRE_PCAP_PROOF"  # Special identifier
                else:
                    messagebox.showerror("No Data", "No connections found in PCAP file.")
                    return
            else:
                # Single connection mode
                selected_connection_string = f"{values[0]}:{values[3]}->{values[1]}:{values[4]} ({values[2]})"
                connections_to_prove = [selected_connection_string]

            # Generate proof
            build_privacy_preserving_proof(connections_to_prove, selected_connection_string, password, save_path,
                                           expiration_days)
            messagebox.showinfo("Success", f"Proof saved successfully to:\n{save_path}")

            # Clear password fields for security
            self.password_entry.delete(0, tk.END)
            self.confirm_password_entry.delete(0, tk.END)
            self.days_var.set("")

        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save proof:\n{str(e)}")
            # Clear password fields even on error
            self.password_entry.delete(0, tk.END)
            self.confirm_password_entry.delete(0, tk.END)
            self.days_var.set("")


def main():
    """Run the Enhanced PCAP Prover application"""
    root = tk.Tk()
    root.title("Enhanced NIZKP PCAP Prover v2.0")
    root.geometry("1200x800")
    root.configure(bg="#F8FAFC")

    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (1200 // 2)
    y = (root.winfo_screenheight() // 2) - (800 // 2)
    root.geometry(f"1200x800+{x}+{y}")

    app = ProverScreen(root)
    app.pack(fill="both", expand=True)

    root.mainloop()


if __name__ == "__main__":
    main()