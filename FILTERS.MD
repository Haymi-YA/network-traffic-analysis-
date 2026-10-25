# Wireshark Display Filters – Network Traffic Analysis

## About This File

This document contains commonly used Wireshark display filters for network traffic analysis, troubleshooting, and cybersecurity investigations.

The filters are organized by protocol and investigation purpose to make packet analysis easier.

**Tool:** Wireshark  
**Filter Type:** Display Filters  
**Purpose:** Network Analysis and Security Investigation

---

## 1. General Network Filters

| Filter | Description |
|---|---|
| `ip` | Display IPv4 packets |
| `ipv6` | Display IPv6 packets |
| `ip.addr == 192.168.1.10` | Traffic involving a specific IP |
| `ip.src == 192.168.1.10` | Traffic from a specific source IP |
| `ip.dst == 192.168.1.10` | Traffic to a specific destination IP |
| `eth` | Ethernet frames |
| `frame.len > 1000` | Frames larger than 1000 bytes |

## 2. DNS Analysis

| Filter | Description |
|---|---|
| `dns` | All DNS packets |
| `dns.flags.response == 0` | DNS queries |
| `dns.flags.response == 1` | DNS responses |
| `dns.qry.name` | Packets containing DNS query names |
| `dns.qry.type == 1` | A record queries |
| `dns.qry.type == 28` | AAAA record queries |
| `dns.flags.rcode != 0` | DNS responses with non-zero response codes |

**Investigation objectives:**
- Identify requested domains.
- Examine DNS queries and responses.
- Identify unsuccessful domain resolution.
- Investigate unusual DNS activity.

## 3. TCP Analysis

| Filter | Description |
|---|---|
| `tcp` | All TCP packets |
| `tcp.flags.syn == 1` | Packets with SYN flag set |
| `tcp.flags.ack == 1` | Packets with ACK flag set |
| `tcp.flags.reset == 1` | TCP reset packets |
| `tcp.flags.fin == 1` | TCP FIN packets |
| `tcp.analysis.retransmission` | TCP retransmissions |
| `tcp.analysis.duplicate_ack` | Duplicate acknowledgments |
| `tcp.port == 443` | TCP traffic using port 443 |
| `tcp.stream == 0` | Packets belonging to TCP stream 0 |

**Investigation objectives:**
- Examine TCP three-way handshakes.
- Identify retransmissions.
- Investigate connection resets.
- Understand communication between clients and servers.

## 4. UDP Analysis

| Filter | Description |
|---|---|
| `udp` | All UDP packets |
| `udp.port == 53` | UDP traffic on port 53 |
| `udp.srcport == 53` | UDP packets from source port 53 |
| `udp.dstport == 53` | UDP packets to destination port 53 |
| `udp.length > 1000` | UDP packets with UDP length greater than 1000 bytes |

**Investigation objectives:**
- Examine UDP communication.
- Identify DNS traffic over UDP.
- Investigate unexpected UDP connections.

## 5. HTTP Analysis

| Filter | Description |
|---|---|
| `http` | HTTP packets |
| `http.request` | HTTP requests |
| `http.response` | HTTP responses |
| `http.request.method == "GET"` | HTTP GET requests |
| `http.request.method == "POST"` | HTTP POST requests |
| `http.response.code == 200` | HTTP responses with status 200 |
| `http.response.code >= 400` | HTTP responses with error status codes |
| `http.host` | Packets containing HTTP host information |

**Investigation objectives:**
- Identify HTTP requests and responses.
- Examine requested hostnames.
- Identify HTTP methods.
- Investigate unencrypted web communication.

## 6. TLS and HTTPS Analysis

| Filter | Description |
|---|---|
| `tls` | TLS packets |
| `tls.handshake` | TLS handshake messages |
| `tls.handshake.type == 1` | Client Hello messages |
| `tls.handshake.type == 2` | Server Hello messages |
| `tls.handshake.extensions_server_name` | TLS packets containing server name information |
| `tls.alert_message` | TLS alert messages |
| `tcp.port == 443` | TCP traffic using port 443 |

**Investigation objectives:**
- Examine TLS handshakes.
- Identify server names where visible.
- Investigate TLS alerts.
- Understand encrypted network communication.

Note: HTTPS commonly uses TLS over TCP port 443, but encrypted traffic may use other ports and protocols. TLS traffic does not necessarily reveal the contents of the communication.

## 7. SSH and SCP Analysis

| Filter | Description |
|---|---|
| `ssh` | SSH packets |
| `tcp.port == 22` | TCP traffic using port 22 |
| `ssh.protocol` | Packets containing SSH protocol information |

**Investigation objectives:**
- Identify SSH connections.
- Examine connection establishment.
- Identify SSH client and server versions when exposed.
- Investigate SCP-related transfers where identifiable.

Note: SCP uses SSH transport. Encrypted file contents are not normally visible in an ordinary packet capture.

## 8. ICMP Analysis

| Filter | Description |
|---|---|
| `icmp` | All ICMP packets |
| `icmp.type == 8` | ICMP Echo Requests |
| `icmp.type == 0` | ICMP Echo Replies |
| `icmp.type == 3` | Destination Unreachable |
| `icmp.type == 11` | Time Exceeded |

**Investigation objectives:**
- Examine ping requests and replies.
- Investigate unreachable destinations.
- Understand basic network diagnostics.

## 9. ARP Analysis

| Filter | Description |
|---|---|
| `arp` | All ARP packets |
| `arp.opcode == 1` | ARP requests |
| `arp.opcode == 2` | ARP replies |
| `arp.duplicate-address-detected` | Detected duplicate IP address condition |

**Investigation objectives:**
- Identify IP-to-MAC address resolution.
- Examine ARP requests and replies.
- Investigate potential duplicate IP address conditions.

## 10. DHCP Analysis

| Filter | Description |
|---|---|
| `dhcp` | DHCP packets |
| `bootp` | BOOTP/DHCP packets in Wireshark |
| `dhcp.option.dhcp == 1` | DHCP Discover |
| `dhcp.option.dhcp == 2` | DHCP Offer |
| `dhcp.option.dhcp == 3` | DHCP Request |
| `dhcp.option.dhcp == 5` | DHCP ACK |

**Investigation objectives:**
- Examine DHCP address assignment.
- Identify DHCP Discover and Offer messages.
- Understand client-server communication during address allocation.

## 11. Email Protocol Analysis

| Filter | Description |
|---|---|
| `smtp` | SMTP traffic |
| `imap` | IMAP traffic |
| `pop` | POP traffic |
| `tcp.port == 25` | TCP traffic on SMTP port 25 |
| `tcp.port == 587` | TCP traffic on submission port 587 |
| `tcp.port == 993` | TCP traffic on IMAPS port 993 |
| `tcp.port == 995` | TCP traffic on POP3S port 995 |

**Investigation objectives:**
- Identify email-related network communication.
- Examine email protocol connections.
- Understand encrypted versus unencrypted email transport.

## 12. Security Investigation Filters

| Filter | Description |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN packets without ACK set |
| `tcp.flags.reset == 1` | TCP reset packets |
| `dns.flags.rcode != 0` | DNS responses with non-zero response codes |
| `icmp.type == 8` | ICMP Echo Requests |
| `tcp.analysis.retransmission` | TCP retransmissions |
| `frame contains "password"` | Frames containing the specified byte sequence |

**Important:** These filters help identify traffic worth investigating. They do not independently prove malicious activity.

---

## 13. Useful Wireshark Investigation Features

| Feature | Purpose |
|---|---|
| Statistics → Protocol Hierarchy | Understand protocol distribution |
| Statistics → Conversations | Examine communication between endpoints |
| Statistics → Endpoints | Identify communicating devices |
| Statistics → I/O Graphs | Visualize traffic over time |
| Follow → TCP Stream | Reconstruct a TCP conversation |
| File → Export Objects | Extract supported transferred objects |

---

## 14. References

- Wireshark Display Filter Reference: https://www.wireshark.org/docs/dfref/
- Wireshark User's Guide: https://www.wireshark.org/docs/wsug_html_chunked/
- Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures

---

**Disclaimer:** This document is maintained for educational and defensive cybersecurity purposes. Filters should be interpreted in the context of the network environment and supporting evidence.
