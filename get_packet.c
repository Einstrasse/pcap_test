
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024

int capture_time;
int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERR_BUF_SIZE];
	pcap_t *handle;

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

	handle = pcap_open_live(dev, PACK_BUF_SIZE, 1, capture_time, errbuf);
	printf("start capturing packet for %d milliseconds...\n", capture_time);
	printf("finished capturing packets\n");
	return EXIT_SUCCESS;
}
