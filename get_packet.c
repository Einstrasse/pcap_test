
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024 * 64
#define DATA_PRINT_LIMIT 300

#define PROTO_TCP 0x06
#define PROTO_UDP 0x11
#define PAYLOAD_DUMP_LIMIT 100


int capture_time;
int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERR_BUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;
	
	capture_time = 1000;
	if (argc < 2) {
		printf("usage: %s [Network Interface name]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	dev = argv[1];

	if (dev == NULL) {
		fprintf(stderr, "Cannot find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Interwork Interface Name: %s\n", dev);

	printf("start capturing packet for %d milliseconds...\n", capture_time);
	handle = pcap_open_live(dev, PACK_BUF_SIZE, 1, capture_time, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	int counter = 0;
	while(1) {
		int status = pcap_next_ex(handle, &header_ptr, &pkt_data);
		if (status == 0) {
			printf("no packet\n");
			continue;
		} else if (status == -1) {
			 fprintf(stderr, "Failed to set buffer size on capture handle : %s\n",
                        pcap_geterr(handle));
			break;
		} else if (status == -2) {
			fprintf(stderr, "Finished reading packet data from packet files\n");
			break;
		}
		counter++;
		struct ether_header *ether_hdr;
		struct ip *ip_hdr;
		struct tcphdr *tcp_hdr;
		ether_hdr = (struct ether_header*)pkt_data;
		if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (struct ip*)(pkt_data + sizeof(struct ether_header));
		} else {
			//printf("not ip proto\n");
			continue;
		}
		int ip_hdr_len = ip_hdr->ip_hl * 4;
		int ip_total_len = ntohs(ip_hdr->ip_len);
		if (ip_hdr->ip_p == PROTO_TCP) {
			tcp_hdr = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + ip_hdr_len);
		} else {
			//printf("not tcp proto\n");
			continue;
		}
	

		printf("-=-=-=-=-=-=-=-=-=-=-=-=#%03d PACKET_LENGTH %d-=-=-=-=-==-=-=-=-=-==\n", counter, header_ptr->len);
		printf("%s", "* Dst MAC = ");
		for (int i=0; i < 6; i++) {
			printf("%02x", ether_hdr->ether_dhost[i]);
			if (i < 5) putchar(':'); else putchar('\n');
		}
		printf("%s", "* Src MAC = ");
		for (int i=0; i < 6; i++) {
			printf("%02x", ether_hdr->ether_shost[i]);
			if (i < 5) putchar(':'); else putchar('\n');
		}
		if (ether_hdr->ether_type == ETHERTYPE_IP) {
			printf("* Network Layer Protocol Type: IPv4\n");
		}
		if (ip_hdr->ip_p == PROTO_TCP) {
			printf("* Transport Layer Protocol Type: TCP\n");
		}
		struct in_addr src_ip = ip_hdr->ip_src;
		struct in_addr dst_ip = ip_hdr->ip_dst;
		char src_ip_str[25];
		char dst_ip_str[25];
		inet_ntop(AF_INET, (void *)&src_ip, src_ip_str, 24);
		inet_ntop(AF_INET, (void *)&dst_ip, dst_ip_str, 24);
		printf("* Src IP Addr = %s\n", src_ip_str);
		printf("* Dst IP Addr = %s\n", dst_ip_str);
		
		printf("%s = %d\n", "* Src Port", ntohs(tcp_hdr->th_sport));
		printf("%s = %d\n", "* Dst Port", ntohs(tcp_hdr->th_dport));
		int tcp_hdr_len = tcp_hdr->th_off * 4;

		int start_offset = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
		u_char *data_ptr = (u_char*)pkt_data;
		data_ptr += start_offset;
		int data_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
		if (data_len == 0) {
			printf("No Payload included\n");
		} else {
			printf("* Packet Payload -------------------\n");
			for (int offset = 0; offset < data_len; offset++) {
				if (offset >= PAYLOAD_DUMP_LIMIT) {
					printf("Payload truncated because of limit option\n");
					break;
				}
				char ch = *(data_ptr+offset);
				if (isprint(ch)) {
					printf("%c", ch);
				} else if (ch == '\r' || ch == '\n') {
					printf("%c", ch);
				} else {
					printf(".");
				}
			}
			putchar('\n');
			printf("* Packet Payload End -------------------\n");
		}
	}

	pcap_close(handle);
	return EXIT_SUCCESS;
}
