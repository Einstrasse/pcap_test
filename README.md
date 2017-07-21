## pcap programming assignment

Best of the Best 6th    
Security Consulting Track    
Jung Hangil

### Compile environment

1. Debian Linuxs (Ubuntu / Kali)
2. gcc
3. pcap library
```
sudo apt install -y libpcap-dev
```

### Compile command

make

### Sources code explaination

get_packet.c - capturing packet for a while and dump the contents of packet.    
dump_if.c - dump network iterface name    
sample.c - sample source code from web site


### Usage
```
make
./get_packet 50
```

On above usage, 50 means the limit number of packet to dump.    
Executing on previleged user(root) is recommended.


### References

Referencing Ethernet header type struct ether_header    
http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html    
Referencing Ip header type struct ip     
http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html     
Referencing ip address structrue, struct in_addr    
https://www.joinc.co.kr/w/man/15/in_addr    
Reference inet_ntop    
https://www.joinc.co.kr/w/Site/TCP_IP/IPv6/IPv6Prog    
Reference tcp header    
http://unix.superglobalmegacorp.com/BSD4.4Lite2/newsrc/netinet/tcp.h.html    

