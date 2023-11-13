# Trouvaille

Find LAN IP configuration from packet sniffing. Usually answers the following questions on an unknown network:

* What's the network address?
* What's the network mask?
* Are protocols leaking information on the network?

## Dependencies

* tcpdump
* tshark
* grepcidr

```
sudo apt install tcpdump tshark grepcidr
```

## Usage

```
$ ./trouvaille.sh
[-] Interface missing
Usage: ./trouvaille.sh [options]
Find network information

arguments:
  -i network interface to check
  -r read from given pcap instead of live capture
```

## Examples

```
$ ./trouvaille.sh -i eth0
Trouvaille

[+] Capturing packets on eth0 for 30 seconds
tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
X packets captured
Y packets received by filter
Z packets dropped by kernel

$ ./trouvaille.sh -r samples/dhcp.pcap
Trouvaille

[+] Reading from samples/dhcp.pcap

[ARP]


[IP]

[+] Looking for src and dst addresses in packets
[+] found IPs for private range 192.168.0.0/16

192.168.0.1
192.168.0.10


[DHCP]

[+] Looking for IP addresses in DHCP
[+] found IPs for private range 192.168.0.0/16

192.168.0.1
192.168.0.10
```
