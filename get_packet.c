
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/if_ether.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024
#define DATA_PRINT_LIMIT 300




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
		ether_hdr = (struct ether_header*)pkt_data;

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
		// if ( header_ptr->len >= 14 && *(pkt_data + 12) == 0x08 && *(pkt_data + 13) == 0x00) {
		// 	printf("* Network Layer Protocol Type: IPv4\n");
		// 	ip_hdr_len = ( *(pkt_data + 14) & 0xf ) * 4;
		// 	printf("* IP Packet header len: %d\n", ip_hdr_len);
		// }
			u_char protocol_4 = *(pkt_data + 23);
		if ( header_ptr->len >= 24 ) {
			if ( protocol_4 == 0x06 ) {
				printf("* Transport Layer Protocol Type: TCP\n");
			} else if ( protocol_4 == 0x11 ) {
				printf("* Transport Layer Protocol Type: UDP\n");
			}
		}
		if ( header_ptr->len >= 34) {
			u_char* srcIP = (u_char*)(pkt_data + 26);
			printf("%s = %d.%d.%d.%d\n", "* Src IP Addr", srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
			u_char* dstIP = (u_char*)(pkt_data + 30);
			printf("%s = %d.%d.%d.%d\n", "* Dst IP Addr", dstIP[0], dstIP[1], dstIP[2], dstIP[3]);
		}
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
