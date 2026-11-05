# HART-IP TCP Traffic Analysis

## 4. Initial TCP Traffic Overview and Conversation Selection

### 4.1 Applying the TCP Display Filter

The investigation began by applying the Wireshark display filter:

```text
tcp
```

This filter displayed all TCP packets in the capture, allowing us to focus on TCP communication before examining individual conversations.

### 4.2 Reviewing TCP Conversations

After filtering the traffic, we opened:

**Statistics → Conversations → TCP**

The TCP Conversations window showed a total of **45 TCP conversations**.

We reviewed the listed conversations to identify communication involving the HART-IP service. One conversation stood out because it involved destination port `5094`, which is associated with HART-IP.

### 4.3 Selecting TCP Stream ID 43

From the 45 TCP conversations, we selected the conversation identified as **Stream ID 43** for detailed investigation.

The selected conversation had the following details:

| Attribute | Observed value |
|---|---|
| Source IP | `192.168.0.101` |
| Source port | `49559` |
| Destination IP | `192.168.0.10` |
| Destination port | `5094` |
| TCP Stream ID | `43` |
| Total packets | 41 |
| Approximate data size | 3 KB |

To isolate this conversation, we applied the following display filter:

```text
tcp.stream == 43
```

This allowed us to examine only the packets belonging to the selected TCP conversation, including the TCP handshake, HART-IP messages, keep-alive exchange, and session termination.

**Finding:** We began with the general TCP filter, reviewed all 45 TCP conversations, and selected Stream ID 43 because its destination port (5094) indicated HART-IP communication. This provided a focused starting point for the detailed protocol analysis.


## 5. TCP Three-Way Handshake

Packets 73–75 demonstrated a successful TCP three-way handshake.

1. Packet 73: Client sent SYN.
2. Packet 74: Server responded with SYN-ACK.
3. Packet 75: Client returned ACK.

This confirmed successful TCP connection establishment between the two devices.

## 5. HART-IP Session Initiation

Packets 76 and 78 showed the HART-IP Session Initiate Request and corresponding Session Initiate Response.

This demonstrated that the application-level HART-IP session was successfully initiated after the TCP connection was established.

## 6. HART-IP Pass Through Communication

Packets 80–106 contained nine visible Pass Through requests and nine corresponding responses.

The HART-IP sequence numbers ranged from 3 to 11.

Each observed request received a corresponding response with the same sequence number.

This demonstrated active bidirectional communication between the two endpoints.

## 7. Keep-Alive Analysis

Packets 108–110 showed a Keep-Alive Request and corresponding Keep-Alive Response.

The exchange occurred approximately 30 seconds after the previous Pass Through response.

The server responded approximately 1.3 milliseconds after the request.

This indicated that the HART-IP session was still responsive.

## 8. Session Termination

Packets 111–114 showed the final communication sequence:

- Packet 111: HART-IP Session Close Request.
- Packet 112: TCP FIN, ACK.
- Packet 113: HART-IP Session Close Response.
- Packet 114: TCP RST.

The final RST indicates a TCP reset following the HART-IP session closure exchange.

The reason for the reset remains undetermined and requires further investigation.

## 9. Security Observations

The investigation identified the following points:

- Successful TCP connection establishment.
- Active bidirectional HART-IP communication.
- Repeated request-response exchanges.
- Successful Keep-Alive response.
- TCP reset following the session closure exchange.

No confirmed malicious activity was established from the inspected packets.

The final TCP reset should be investigated further to determine whether it reflects expected application behavior or an abnormal termination.

## 10. Conclusion

The PCAP analysis revealed an active HART-IP communication session between 192.168.0.101 and 192.168.0.10 over TCP port 5094.

The communication followed a recognizable sequence: TCP connection establishment, HART-IP session initiation, repeated Pass Through exchanges, Keep-Alive communication and session closure.

The investigation demonstrates how Wireshark can be used to analyze TCP behavior and inspect industrial application-layer communication.

Further examination of HART-IP payloads and the final TCP reset would provide additional insight into the nature of the communication.

## 11. Skills Demonstrated

- Wireshark packet analysis
- TCP three-way handshake investigation
- TCP session analysis
- HART-IP protocol inspection
- Network communication timeline reconstruction
- Industrial network security analysis
- Security observations and technical reporting
