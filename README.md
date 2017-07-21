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


### Usage
```
make
./get_packet eth0
```

On above usage, monitoring device name is eth0 (ethernet interface).
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

