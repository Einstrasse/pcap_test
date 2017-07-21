
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024
#define DATA_PRINT_LIMIT 300

#define PROTO_TCP 0x06
#define PROTO_UDP 0x11

int capture_time;
int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERR_BUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;
	int ether_len = 14;
	int ip_hdr_len = -1;
	u_char tcp_header_len = 0;
	capture_time = 1000;
	int capture_packet_num_limit = 1;
	if (argc < 2) {
		printf("usage: %s [Network Interface name]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	//capture_packet_num_limit = atoi(argv[1]);
	capture_packet_num_limit = 10000;

	//dev = pcap_lookupdev(errbuf);
	dev = argv[1];

	if (dev == NULL) {
		fprintf(stderr, "Cannot find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Interwork Interface Name: %s\n", dev);

	printf("start capturing packet for %d milliseconds...\n", capture_time);
	handle = pcap_open_live(dev, PACK_BUF_SIZE, 1, capture_time, errbuf);
	//handle = pcap_open_live("dum0", PACK_BUF_SIZE, 1, capture_time, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	int counter = 0;
	while(1) {
		int status = pcap_next_ex(handle, &header_ptr, &pkt_data);
		if (status == 0) {
			continue;
		} else if (status == -1) {
			 fprintf(stderr, "Failed to set buffer size on capture handle : %s\n",
                        pcap_geterr(handle));
			break;
		}
		counter++;
		if (counter > capture_packet_num_limit) break;
		struct ether_header *ether_hdr;
		struct ip *ip_hdr;
		ether_hdr = (struct ether_header*)pkt_data;
		if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (struct ip*)(pkt_data + sizeof(struct ether_header));
		} else {
			//not IP protocol
			continue;
		}
		if (ip_hdr->ip_p != PROTO_TCP) {
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
		
		// u_char* srcIP = (u_char*)(pkt_data + 26);
		// printf("%s = %d.%d.%d.%d\n", "* Src IP Addr", srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
		// u_char* dstIP = (u_char*)(pkt_data + 30);
		// printf("%s = %d.%d.%d.%d\n", "* Dst IP Addr", dstIP[0], dstIP[1], dstIP[2], dstIP[3]);
		
		if (ip_hdr_len != -1 && header_ptr->len >= ip_hdr_len + ether_len) {
			u_short *srcPort = (u_short*)(pkt_data + ip_hdr_len + ether_len);
			u_short *dstPort = (u_short*)(pkt_data + ip_hdr_len + ether_len + 2);

			printf("%s = %d\n", "* Src Port", ntohs(*srcPort));
			printf("%s = %d\n", "* Dst Port", ntohs(*dstPort));

			tcp_header_len = *(pkt_data + ip_hdr_len + ether_len + 12);
			tcp_header_len = tcp_header_len & 0xf0;
			tcp_header_len = (tcp_header_len >> 4);
			tcp_header_len *= 4;
		}
		if (tcp_header_len > 0 &&header_ptr->len >= ip_hdr_len + ether_len + tcp_header_len) {
			printf("* Packet Payload -------------------\n");
			int cnt = 0;
			for (int idx = ip_hdr_len + ether_len + tcp_header_len; idx < header_ptr->len; idx++, cnt++) {
				if (cnt > DATA_PRINT_LIMIT) break;
				char ch = *(pkt_data + idx);
				if (isprint(ch)) {
					printf("%c", *(pkt_data + idx));
				} else if (ch == '\r' || ch == '\n') {
					printf("%c", ch);
				} else {
					printf(".");
				}
			}
			putchar('\n');
			printf("* Packet Payload End -------------------\n");
		} else {
			printf("There is no Data\n");
		}
	}


	pcap_close(handle);
	return EXIT_SUCCESS;
}
