# UDP Packet Analysis – HART-IP Communication

## 1. Objective

Analyze UDP traffic in a provided network packet capture (PCAP) using Wireshark. The investigation focuses on understanding HART-IP communication, identifying communicating hosts and UDP conversations, examining session establishment and termination, and investigating ICMP communication errors.

The goal is to establish a baseline of normal UDP communication and identify observations that may be relevant to network security.

## 2. Tools and Evidence

- **Wireshark:** Network packet analysis
- **PCAP:** hart_ip.pcap
- **Transport Protocol:** UDP
- **Application Protocol:** HART-IP

Useful Wireshark filters:

```wireshark
udp
```

```wireshark
udp.stream == 0
```

```wireshark
udp.stream == 1
```

```wireshark
icmp
```

```wireshark
frame.number == 27
```

## 3. Network Communication Overview

The capture shows HART-IP communication between two hosts.

| Field | Value |
|---|---|
| Client IP | `192.168.0.101` |
| Server IP | `192.168.0.10` |
| Transport protocol | UDP |
| Application protocol | HART-IP |
| Capture date | March 19, 2012 |

### 3.1 UDP Conversation Analysis

Wireshark Statistics → Conversations → UDP identified two UDP conversations:

| Stream | Source endpoint | Destination endpoint | Packets |
|---|---|---|---:|
| 0 | `192.168.0.101:49905` | `192.168.0.10:5094` | 1 |
| 1 | `192.168.0.10:5095` | `192.168.0.101:49905` | 23 |

The conversations show different UDP endpoint pairs. Stream 0 contains the initial request according to the stream-filter investigation, while Stream 1 contains the subsequent response and communication exchanges.

**Note:** The individual packet details also showed Stream index 1 for a Session Initiate Response. The stream and port assignments should be cross-checked against the original PCAP before treating the conversation table as a definitive mapping of every packet. Wireshark stream indexes represent endpoint pairs, not necessarily separate application sessions.

## 4. UDP Communication Analysis

### 4.1 Session Establishment

The communication begins with a HART-IP Session Initiate Request from the client.

The corresponding server response contains:

| HART-IP Field | Value |
|---|---|
| Version | 1 |
| Message Type | Response (1) |
| Message ID | Session Initiate (0) |
| Status | 0 |
| Sequence Number | 2 |
| Message Length | 13 |

The matching sequence number and message ID establish a relationship between the request and response.

Status 0 indicates that no HART-IP protocol error was reported.

### 4.2 Pass Through Communication

Following session initiation, the client and server exchange nine Pass Through request-response pairs.

The observed sequence numbers range from 3 to 11.

The Pass Through messages carry HART commands between the master and field device.

One example is Command 0 (Read Unique Identifier).

The field device responds with identification information, including:

- Long Address: `264e0000d2`
- Expanded Device Type: `0x264e`
- HART Universal Revision: 7
- Device Revision: 4
- Software Revision: 1
- Device ID: `0000d2`

The response reports Status 0.

These exchanges demonstrate bidirectional UDP communication carrying industrial application-layer messages.

### 4.3 Device Status Observation

The response to Command 0 reports:

```text
Device Status: 0xd0
```

The same status value appears in the response to Command 48 (Read Additional Device Status).

Command 48 returns:

| Field | Value |
|---|---|
| Response Code | 0 |
| Device Status | `0xd0` |
| Device-Specific Status | `100407000000` |
| Extended Device Status | `0x02` |
| Device Operating Mode | 0 |
| Standardized Status 0–3 | `0x00` |

The value `0xd0` contains device malfunction, configuration changed, and more status available flags under the standard HART device-status bit definitions.

These indicators warrant further investigation using manufacturer documentation and device maintenance records. They do not independently establish malicious activity or unauthorized changes.

### 4.4 Session Maintenance – Keep Alive

Packets 23 and 24 contain the Keep Alive exchange.

| Packet | Message | Sequence |
|---|---|---:|
| 23 | Keep Alive Request | 12 |
| 24 | Keep Alive Response | 12 |

The Keep Alive Request occurs approximately 30 seconds after the last observed Pass Through Response.

The server responds approximately 1.3 milliseconds later.

This indicates that the HART-IP communication remained responsive during the observed exchange.

### 4.5 Session Termination – Session Close

Packets 25 and 26 contain the session termination exchange.

| Packet | Message | Sequence |
|---|---|---:|
| 25 | Session Close Request | 13 |
| 26 | Session Close Response | 13 |

The server returns a Session Close Response with:

- Message Type: Response
- Message ID: Session Close (1)
- Status: 0
- Sequence Number: 13
- Message Length: 8 bytes

The matching sequence number and Status 0 indicate that the server processed the session-close request without reporting an application-level protocol error.

## 5. ICMP Investigation – Destination Unreachable

Packet 27 contains an ICMP Destination Unreachable message.

| ICMP Field | Value |
|---|---|
| Type | 3 – Destination Unreachable |
| Code | 3 – Port Unreachable |
| Checksum | `0x7ede` |
| Checksum Status | Good |

The ICMP message quotes the following original IP and UDP datagram:

| Field | Value |
|---|---|
| Source IP | `192.168.0.10` |
| Destination IP | `192.168.0.101` |
| Source UDP Port | 5095 |
| Destination UDP Port | 49905 |
| UDP Length | 16 bytes |
| UDP Payload | 8 bytes |
| UDP Stream Index | 1 |

The quoted UDP payload contains a HART-IP Session Close Response with sequence number 13 and Status 0.

### Analysis

The ICMP message indicates that UDP port 49905 on the destination host was unavailable when the quoted datagram was processed.

One possible explanation is that the client had already closed or stopped listening on its UDP socket after completing the application-level session termination.

However, the packet capture does not establish the exact cause. Further investigation would be needed to determine whether the behavior was expected or resulted from UDP socket lifecycle or communication-handling issues.

**Important distinction:** The HART-IP Session Close Response reports Status 0, while the ICMP message reports a transport-layer port-unreachable condition. These observations should not be confused or interpreted as proof that the application-level session closure failed.

## 6. Security Findings

The investigation identified the following observations:

| Observation | Security relevance |
|---|---|
| Two UDP conversations | Different endpoint pairs were identified during the observed communication. |
| Session initiation | Establishes the beginning of HART-IP communication. |
| Nine Pass Through exchanges | Provides a baseline of repeated industrial protocol transactions. |
| Sequential message numbers | Helps correlate requests and responses. |
| Keep Alive exchange | Demonstrates session maintenance and endpoint responsiveness. |
| Session Close exchange | Shows application-level session termination. |
| Device Status `0xd0` | Indicates device diagnostic flags requiring further investigation. |
| ICMP Port Unreachable | Identifies a UDP destination port that was unavailable. |

### Security Assessment

The observed traffic demonstrates structured, bidirectional HART-IP communication over UDP.

The capture provides evidence of successful application-level responses, repeated industrial device interactions, session maintenance, and session termination.

The ICMP Port Unreachable message and device-status indicators are noteworthy findings that require additional context.

No direct evidence of malicious activity was established from the analyzed packets.

## 7. Conclusion

This Wireshark investigation demonstrates how UDP supports HART-IP communication in an industrial network.

The analysis identified the communicating hosts, examined UDP conversations, correlated application-level requests and responses, and followed the communication through session establishment, data exchange, keep-alive, and termination.

The investigation also identified an ICMP Port Unreachable message referencing the Session Close Response and device-status indicators that warrant further examination.

From a network security perspective, understanding normal UDP communication patterns is important for establishing a baseline, identifying unexpected behavior, and investigating potential anomalies in industrial environments.

This analysis provides a foundation for further investigation of industrial network protocols and their security implications.
