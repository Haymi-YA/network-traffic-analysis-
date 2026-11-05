# HART-IP PCAP Analysis – TCP Investigation

## 1. Overview

This report documents the TCP analysis of a sample packet capture (PCAP) containing HART-IP communication. The investigation was conducted using Wireshark to identify TCP conversations, examine connection establishment, inspect HART-IP messages, and review session termination.

The capture contains both TCP and UDP traffic. This report focuses exclusively on the TCP communication. UDP analysis will be documented separately.

## 2. Objectives

The objectives of this investigation were to:

- Identify TCP conversations and communicating hosts.
- Examine the TCP three-way handshake.
- Identify HART-IP session initiation and communication.
- Inspect request and response exchanges.
- Examine session keep-alive and termination messages.
- Identify unusual activity that may require further investigation.

## 3. Tools and Environment

| Item | Details |
|---|---|
| Analysis tool | Wireshark |
| Evidence | Sample HART-IP PCAP |
| Protocol | TCP / HART-IP |
| Primary filter | `tcp` |
| Conversation filter | `tcp.stream == 43` |
| HART-IP port | TCP 5094 |

## 4. Initial TCP Traffic Overview

The Wireshark Conversations window showed:

- 45 TCP conversations.
- Most of the visible TCP conversations involved `192.168.0.100` communicating with external or remote IP addresses.
- Several connections used destination port 80 (HTTP), while one visible connection used port 443 (HTTPS).
- An internal connection between `192.168.0.100` and `192.168.0.101` used destination port 445 (SMB).
- A separate conversation between `192.168.0.101` and `192.168.0.10` used destination port 5094.

The conversation using TCP port 5094 was selected for further investigation because port 5094 is associated with HART-IP communication.

**Note:** The observation that `192.168.0.100` initiated many visible conversations does not establish that it initiated every TCP connection in the capture.

## 5. Detailed HART-IP TCP Conversation

### 5.1 Communication Details

The selected conversation had the following characteristics:

| Attribute | Observed value |
|---|---|
| Source IP | `192.168.0.101` |
| Source port | `49559` |
| Destination IP | `192.168.0.10` |
| Destination port | `5094` |
| Protocol | TCP / HART-IP |
| TCP stream | 43 |
| Total packets | 41 |
| Approximate data size | 3 KB |

The source port `49559` is an ephemeral client-side port, while destination port `5094` is the HART-IP service port.

### 5.2 TCP Three-Way Handshake

The connection began with a successful TCP three-way handshake:

| Packet | Communication | TCP flag | Meaning |
|---|---|---|---|
| 73 | `192.168.0.101` → `192.168.0.10` | SYN | Client requests a connection |
| 74 | `192.168.0.10` → `192.168.0.101` | SYN, ACK | Server acknowledges and responds |
| 75 | `192.168.0.101` → `192.168.0.10` | ACK | Client confirms the connection |

**Finding:** The three-way handshake completed successfully, establishing the TCP connection between the two hosts.

### 5.3 HART-IP Session Initiation

After the TCP connection was established, HART-IP session initiation messages were exchanged:

| Packet | Message | Sequence |
|---|---|---|
| 76 | Session Initiate Request | 2 |
| 78 | Session Initiate Response | 2 |

The request was sent by `192.168.0.101`, and the response came from `192.168.0.10`.

**Finding:** The packet sequence shows that the TCP connection was followed by HART-IP session initiation and a corresponding response.

### 5.4 HART-IP Pass-Through Communication

The packet capture showed nine Pass Through Request/Response exchanges.

The observed sequence numbers ranged from 3 to 11.

| Communication | Observed messages |
|---|---|
| Pass-through requests | 9 |
| Pass-through responses | 9 |
| Sequence numbers | 3–11 |

These exchanges indicate that the two endpoints continued communicating after the HART-IP session was established.

**Finding:** The repeated request-and-response pattern is consistent with ongoing HART-IP communication. The packet names alone do not establish whether the underlying operations were successful or whether the messages contained abnormal commands.

### 5.5 Keep-Alive Messages

The capture also contained:

| Packet | Message | Sequence |
|---|---|---|
| 108 | Keep Alive Request | 12 |
| 109 | Keep Alive Response | 12 |

The request was observed at `15:13:57.153878 UTC`, and the response at `15:13:57.155206 UTC`.

The response followed approximately 1.3 milliseconds after the request.

**Finding:** The endpoint responded promptly to the keep-alive request, indicating that the HART-IP session was still responding at that point in the capture.

### 5.6 Session Termination

The final HART-IP messages included:

| Packet | Message |
|---|---|
| 111 | Session Close Request |
| 112 | TCP FIN, ACK |
| 113 | Session Close Response |
| 114 | TCP RST |

The client sent a HART-IP Session Close Request. A TCP FIN, ACK was then observed, followed by the HART-IP Session Close Response and a TCP Reset (RST).

**Finding:** The HART-IP session close messages indicate an attempt to terminate the application-level session. The subsequent TCP RST is worth documenting and investigating further. However, a reset by itself does not prove malicious activity. Additional packet details and endpoint context would be needed to determine why it occurred.

### 5.7 TCP Connection Termination and SMB Communication

After examining the HART-IP conversation, we expanded the investigation to the remaining TCP traffic using the following filters:

| Display filter | Observed packets |
|---|---:|
| `tcp` | 87 |
| `tcp.flags.fin == 1` | 44 |
| `tcp.flags.reset == 1` | 1 |
| `tcp.len > 0` | 26 |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | 1 |

#### A. TCP Connection Termination (FIN, ACK)

The FIN, ACK inspection revealed that many termination packets originated from `192.168.0.100` and were directed to multiple external IP addresses.

Most of these connections used destination port 80 (HTTP), with different ephemeral source ports.

Examples include:

| Packet | Source IP | Destination IP | Destination port | TCP flags |
|---|---|---|---|---|
| 28 | 192.168.0.100 | 64.185.181.238 | 80 | FIN, ACK |
| 29 | 192.168.0.100 | 23.15.7.51 | 80 | FIN, ACK |
| 30 | 192.168.0.100 | 23.15.7.51 | 80 | FIN, ACK |
| 31 | 192.168.0.100 | 72.21.91.19 | 80 | FIN, ACK |
| 32 | 192.168.0.100 | 205.251.253.243 | 80 | FIN, ACK |

These packets occurred within approximately 100 milliseconds, between 15:13:24.947 and 15:13:25.047 UTC.

**Interpretation:** Host `192.168.0.100` was sending TCP connection termination messages to multiple remote hosts. This indicates that several previously established connections were being closed. The FIN packets alone do not establish which host originally initiated those connections or why they were closed.

One additional observation was packet 70, a 93-byte TLSv1 Encrypted Alert sent from `192.168.0.100` to `74.125.159.99`. The encrypted alert contents were not available from the packet summary.

#### B. SMB Communication – TCP Stream 44

A separate internal TCP conversation was identified as Stream 44, involving communication between `192.168.0.100` and `192.168.0.101` over destination port 445, commonly associated with SMB.

| Attribute | Observed value |
|---|---|
| TCP Stream | 44 |
| Source IP | `192.168.0.100` |
| Destination IP | `192.168.0.101` |
| Destination port | 445 |
| Protocol | SMB |

The following packets were examined:

| Packet | Protocol | Observation |
|---|---|---|
| 107 | TCP | ACK from `192.168.0.100` to `192.168.0.101` |
| 115 | SMB | Session message; Check Directory, Directory: `\` |
| 116 | TCP | ACK from `192.168.0.100` to `192.168.0.101` |

Packet 115 indicates directory-related SMB activity between the two internal hosts. Packet 116 is a subsequent TCP acknowledgment.

**Interpretation:** The traffic demonstrates internal SMB communication between the two hosts. However, the available packet summaries do not establish whether the directory operation succeeded, what share was accessed, or whether any files were transferred.

#### C. Security Relevance

The TCP investigation identified three notable communication patterns:

1. Multiple TCP connections from `192.168.0.100` to external hosts were being terminated.
2. TLS encrypted alert traffic was observed during the same period.
3. Internal SMB communication occurred between `192.168.0.100` and `192.168.0.101`.

These observations provide useful information about external and internal network activity. Further examination of application-layer messages, SMB responses, and endpoint logs would be necessary to determine whether the activity was expected or suspicious.

## 6. Security Observations

| Observation | Security interpretation |
|---|---|
| TCP connection to port 5094 | Consistent with HART-IP communication |
| Successful three-way handshake | TCP connection was established |
| Session initiation request and response | HART-IP session setup was observed |
| Nine pass-through request/response pairs | Continued HART-IP message exchanges |
| Keep-alive request and response | Endpoint responded to a session-maintenance message |
| TCP RST during termination | Requires further investigation; not automatically malicious |

### Items Requiring Further Investigation

1. Inspect the contents of the HART-IP pass-through messages to understand the operations being requested.
2. Examine the TCP RST packet and surrounding packet details to determine why the connection was reset.
3. Confirm the meaning of the observed `0x86` value by identifying the exact HART-IP field in which it appears.
4. Correlate the communication with device logs or other network evidence, if available.

## 7. Conclusion

The TCP investigation identified a HART-IP conversation between `192.168.0.101` and `192.168.0.10` using TCP port 5094.

The connection completed the TCP three-way handshake, followed by HART-IP session initiation, nine pass-through request/response exchanges, and a keep-alive exchange. Session closure messages were also observed, followed by a TCP reset.

Based on the packet information reviewed, the communication follows an identifiable HART-IP request-and-response sequence. The TCP reset and the meaning of the `0x86` value require additional investigation before drawing further security conclusions.

No confirmed malicious activity has been established from the TCP evidence reviewed so far.

## 8. Wireshark Filters Used

| Purpose | Display filter |
|---|---|
| Display TCP traffic | `tcp` |
| Select the HART-IP TCP conversation | `tcp.stream == 43` |
| Display TCP connection requests | `tcp.flags.syn == 1` |
| Display TCP packets carrying data | `tcp.len > 0` |
| Display TCP connection resets | `tcp.flags.reset == 1` |
| Display TCP connection termination flags | `tcp.flags.fin == 1` |

## 9. Skills Demonstrated

- Wireshark TCP traffic analysis
- TCP three-way handshake investigation
- TCP conversation identification
- HART-IP protocol inspection
- Request-and-response analysis
- Session management and termination analysis
- Basic network security investigation

---

**Next stage:** UDP traffic analysis will be documented in a separate section, using the same evidence-based approach.
