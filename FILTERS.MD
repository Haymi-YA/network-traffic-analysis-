Protocol / purpose	                          Wireshark filter
DNS	                                                dns
TCP                                                	tcp
UDP                                                	udp
HTTP                                              	http
TLS                                                	tls
SSH	                                                ssh
ICMP	                                              icmp
ARP	                                                arp
DHCP	                                              dhcp
Specific IP	                                        ip.addr == 192.168.1.10
Specific port                                      	tcp.port == 443
DNS queries	                                        dns.flags.response == 0
TCP SYN packets	                                    tcp.flags.syn == 1
