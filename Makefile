all : arp_spoofing

arp_spoofing: main.o
	g++ -g -o arp_spoofing main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_spoofing
	rm -f *.o
