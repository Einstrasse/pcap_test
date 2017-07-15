dump_if: dump_if.c
	gcc -o dump_if dump_if.c -lpcap

clean:
	rm dump_if