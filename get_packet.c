
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024

int capture_time;
int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERR_BUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;


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
		printf("\t#%03d PACKET_LENGTH %d\n", counter, header_ptr->len);
		printf("%12s", "Dest MAC = ");
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
		if ( *(pkt_data + 12) == 0x08 && *(pkt_data + 13) == 0x00) {
			printf("Type: IPv4\n");
			int ip_hdr_len = ( *(pkt_data + 14) & 0xf ) * 4;
			printf("IP Packet header len: %d\n", ip_hdr_len);
		}
		printf(" ============== PACKET HEX DATA ===============\n");
		for (int i = 0; i < header_ptr->len; i++) {
			if ( (*(pkt_data + i ) & 0xff) >= 0x10) {
				printf("%x ", *(pkt_data + i) & 0xff);
			} else {
				printf("0%x ", *(pkt_data + i) & 0xff);
			}
			if (i % 16 == 15) {
				putchar('\n');
			}
			 else if (i % 8 == 7) {
				putchar(' ');
			}
		}
		putchar('\n');
	}


	pcap_close(handle);
	return EXIT_SUCCESS;
}
