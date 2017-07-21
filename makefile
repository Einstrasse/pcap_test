get_packet: get_packet.c
	gcc -o get_packet get_packet.c -lpcap -Wall

clean:
	rm dump_if get_packet sample