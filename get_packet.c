
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024
#define DATA_PRINT_LIMIT 16


// uint32_t htonl(uint32_t hostlong);
// uint16_t htons(uint16_t hostshort);
// uint32_t ntohl(uint32_t netlong);
// uint16_t ntohs(uint16_t netshort);

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
	if (argc < 2) {
		printf("usage: %s [capture time in milliseconds]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	capture_time = atoi(argv[1]);

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Cannot find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Default Device: %s\n", dev);

	printf("start capturing packet for %d milliseconds...\n", capture_time);
	handle = pcap_open_live(dev, PACK_BUF_SIZE, 1, capture_time, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	printf("finished capturing packets\n");
	int counter = 0;
	while( pcap_next_ex(handle, &header_ptr, &pkt_data) ) {
		counter++;
		printf("-=-=-=-=-=-=-=-=-=-=-=-=#%03d PACKET_LENGTH %d-=-=-=-=-==-=-=-=-=-==\n", counter, header_ptr->len);
		printf("%12s", "Dst MAC = ");
		for (int i=0; i < 6; i++) {
			if ( (*(pkt_data + i ) & 0xff) >= 0x10) {
				printf("%x", *(pkt_data + i) & 0xff);
			} else {
				printf("0%x", *(pkt_data + i) & 0xff);
			}
			if (i < 5) putchar(':'); else putchar('\n');
		}
		printf("%12s", "Src MAC = ");
		for (int i=6; i < 12; i++) {
			if ( (*(pkt_data + i ) & 0xff) >= 0x10) {
				printf("%x", *(pkt_data + i) & 0xff);
			} else {
				printf("0%x", *(pkt_data + i) & 0xff);
			}
			if (i < 11) putchar(':'); else putchar('\n');
		}
		if ( header_ptr->len >= 14 && *(pkt_data + 12) == 0x08 && *(pkt_data + 13) == 0x00) {
			printf("Network Layer Protocol Type: IPv4\n");
			ip_hdr_len = ( *(pkt_data + 14) & 0xf ) * 4;
			printf("IP Packet header len: %d\n", ip_hdr_len);
		}
			u_char protocol_4 = *(pkt_data + 23);
		if ( header_ptr->len >= 24 ) {
			if ( protocol_4 == 0x06 ) {
				printf("Transport Layer Protocol Type: TCP\n");
			} else if ( protocol_4 == 0x11 ) {
				printf("Transport Layer Protocol Type: UDP\n");
			}
		}
		if ( header_ptr->len >= 34) {
			u_char* srcIP = pkt_data + 26;
			printf("%12s = %d.%d.%d.%d\n", "Src IP Addr", srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
			u_char* dstIP = pkt_data + 30;
			printf("%12s = %d.%d.%d.%d\n", "Dst IP Addr", dstIP[0], dstIP[1], dstIP[2], dstIP[3]);
		}
		if (ip_hdr_len != -1 && header_ptr->len >= ip_hdr_len + ether_len) {
			u_short *srcPort = pkt_data + ip_hdr_len + ether_len;
			u_short *dstPort = pkt_data + ip_hdr_len + ether_len + 2;

			printf("%10s = %d\n", "Src Port", ntohs(*srcPort));
			printf("%10s = %d\n", "Dst Port", ntohs(*dstPort));

			tcp_header_len = *(pkt_data + ip_hdr_len + ether_len + 12) / 4;
		}
		if (tcp_header_len > 0 &&header_ptr->len >= ip_hdr_len + ether_len + tcp_header_len) {
			printf("Packet Payload\n");
			int cnt = 0;
			for (int idx = ip_hdr_len + ether_len + tcp_header_len; idx < header_ptr->len; idx++) {
				if (isprint(*(pkt_data + idx))) {
					printf("%c", *(pkt_data + idx));
				} else {
					printf(".");
				}
			}
			putchar('\n');
		} else {
			printf("There is no Data\n");
		}
		printf("-===-=-=-=-=-=-=-==-==-=-=-=-==-=-=--=-=-=--=-=\n");
		// printf(" ============== PACKET HEX DATA ===============\n");
		// for (int i = 0; i < header_ptr->len; i++) {
		// 	if ( (*(pkt_data + i ) & 0xff) >= 0x10) {
		// 		printf("%x ", *(pkt_data + i) & 0xff);
		// 	} else {
		// 		printf("0%x ", *(pkt_data + i) & 0xff);
		// 	}
		// 	if (i % 16 == 15) {
		// 		putchar('\n');
		// 	}
		// 	 else if (i % 8 == 7) {
		// 		putchar(' ');
		// 	}
		// }
		// putchar('\n');
	}


	pcap_close(handle);
	return EXIT_SUCCESS;
}
