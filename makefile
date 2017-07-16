get_packet: get_packet.c
	gcc -o get_packet get_packet.c -lpcap

#sample: sample.c
#	gcc -o sample sample.c -lpcap
	
#dump_if: dump_if.c
#	gcc -o dump_if dump_if.c -lpcap

clean:
	rm dump_if get_packet sample