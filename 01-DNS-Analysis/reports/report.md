# DNS Traffic Analysis

## 1. Objective

The objective of this investigation is to examine DNS traffic in a packet capture using Wireshark, identify DNS queries and responses, understand DNS record types, and investigate unsuccessful domain lookups.

## 2. Tools and Evidence

- **Tool:** Wireshark
- **Evidence:** `dns.cap`
- **Protocol:** DNS
- **Display filter:** `dns`

## 3. Initial Observations

The capture contains DNS queries and responses involving two client IP addresses:

- `192.168.170.8`
- `192.168.170.56`

Two DNS server addresses observed are:

- `192.168.170.20`
- `217.13.4.24`

The capture includes A, AAAA, TXT, PTR, NS, SRV, LOC, MX, and ANY query types.

## 4. Investigation of Failed DNS Lookups

The investigation includes responses with the NXDOMAIN response code. NXDOMAIN indicates that the DNS server reports that the requested domain name does not exist.

Domains observed in the queries include `www.example.notginh` and names under `utelsystems.local`.

### 4.1 Failed DNS Responses

Using the Wireshark display filter `dns.flags.response == 1 && dns.flags.rcode == 3`, six unsuccessful DNS responses were identified.

Wireshark displayed the message "No such name", corresponding to the DNS response code NXDOMAIN (RCODE 3).

This indicates that the DNS server reported that the requested domain names did not exist.

One observed example was `www.example.notginh`. Other unsuccessful requests involved names under `utelsystems.local`.

These failures may be associated with unavailable domains or DNS configuration issues. Their significance requires additional investigation.

### 4.2 Analysis of Failed Domain Lookups

Six NXDOMAIN responses were identified, representing five unique queried domain names.

The observed requests included:

- One lookup for www.example.notginh.
- Three LDAP SRV record lookups under utelsystems.local.
- Two A-record lookups for GRIMM.utelsystems.local.

The LDAP SRV queries are particularly relevant because they are used to discover LDAP services, including Active Directory domain controllers.

The repeated lookup for GRIMM.utelsystems.local indicates that the same hostname was queried twice. Further investigation would be required to establish why.

The failed internal-domain lookups may indicate DNS configuration or service discovery problems. However, the available evidence does not establish malicious activity.

### 4.3 DNS Server Response Analysis

The six unsuccessful DNS responses originated from two DNS servers:

- 192.168.170.20 returned one NXDOMAIN response for www.example.notginh.
- 217.13.4.24 returned five NXDOMAIN responses involving utelsystems.local.

The five unsuccessful responses from 217.13.4.24 involved three LDAP SRV record lookups and two A-record lookups for GRIMM.utelsystems.local.

This indicates that the two DNS servers handled different groups of queries in the observed traffic.

The internal-domain resolution failures warrant further investigation to determine whether they resulted from DNS configuration issues, unavailable services, or other environmental conditions.

### 4.4 Investigation of Successful DNS Lookups

To identify successful DNS responses, the following Wireshark display filter was applied:

```wireshark
dns.flags.response == 1 && dns.flags.rcode == 0
```

The filter returned 13 DNS response packets. All 13 responses originated from `192.168.170.20` and were destined for `192.168.170.8`.

The DNS responses contained several record types, including A, AAAA, TXT, MX, LOC, PTR, CNAME, ANY, and NS.

**Observed successful DNS responses included:**

- `google.com` – TXT, MX, and LOC queries.
- `www.netbsd.org` – A and AAAA records.
- `www.google.com` – CNAME response pointing to `www.l.google.com`.
- `www.l.google.com` – AAAA query response.
- `www.example.com` – AAAA query response.
- `www.isc.org` – ANY query returning A and AAAA records.
- `isc.org` – NS query returning name server records.

Two reverse DNS lookups were also observed:

- `104.9.192.66.in-addr.arpa` returned a PTR record resolving to `66-192-9-104.gen.twtelecom.net`.
- `1.0.0.127.in-addr.arpa` returned a PTR record resolving to `localhost`.

**Returned IP addresses:**

The following IPv4 addresses were visible in the DNS response summaries:

- `204.152.190.12`
- `216.239.37.26`
- `64.233.167.25`
- `66.102.9.25`
- `216.239.57.25`
- `216.239.57.26`
- `204.152.184.88`

The observed IPv6 addresses included:

- `2001:4f8:4:7:2e0:81ff:fe52:9a6b`
- `2001:4f8:0:2::d`

The IPv6 address for `www.netbsd.org` appeared in two separate responses.

**DNS Response Flags Analysis**

Further examination of the DNS response flags showed:

- Authoritative Answer (AA): Not authoritative for the queried domain.
- Recursion Available (RA): The responding server supports recursive queries.

These observations indicate that the responding DNS server supports recursive DNS resolution and does not identify itself as authoritative for the queried domains.

**Additional Observation**

Although all 13 responses returned the NOERROR response code, some did not contain the requested record in the Answers section.

For example, the TXT query for `google.com` and the AAAA queries for `www.l.google.com` and `www.example.com` did not display the requested records in the Answers section.

This demonstrates that NOERROR indicates successful DNS query processing but does not necessarily mean that the requested record was returned.

### 4.5 Comparison of Successful and Unsuccessful DNS Responses

The investigation identified two different DNS response outcomes:

- **NXDOMAIN (RCODE 3):** The DNS server reported that the requested domain name did not exist.
- **NOERROR (RCODE 0):** The DNS server successfully processed the query, although the requested record was not necessarily returned.

Six NXDOMAIN responses and 13 NOERROR responses were identified using separate Wireshark display filters.

The unsuccessful responses involved two DNS servers, while all 13 successful responses originated from `192.168.170.20` and were destined for `192.168.170.8`.

The results demonstrate the importance of examining both DNS response codes and the Answers section when investigating DNS traffic.

## 5. Security Considerations

Unsuccessful DNS lookups may result from typographical errors, configuration issues, unavailable domains, or attempts to locate internal services. Further investigation is necessary before classifying any activity as suspicious or malicious.

## 6. Conclusion

This investigation demonstrates how Wireshark can be used to identify DNS clients, DNS servers, query types, and unsuccessful DNS resolutions. The observations provide a foundation for further network traffic analysis.
