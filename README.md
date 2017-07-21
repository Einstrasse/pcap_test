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

Referencing Ethernet header type struct    
http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html    
