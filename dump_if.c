#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#define PCAP_ERR_BUF_SIZE 1024

int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERR_BUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Cannot find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", dev);
	return EXIT_SUCCESS;
}
