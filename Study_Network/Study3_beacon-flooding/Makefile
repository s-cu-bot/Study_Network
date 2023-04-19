all : beacon_flooding

beacon_flooding: main.o
	g++ -g -o beacon_flooding main.o -lpcap

main.o:
	g++ -g -c -o main.o main.c

clean:
	rm -f beacon_flooding
	rm -f *.o

