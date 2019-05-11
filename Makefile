all: netfilter_block

netfilter_block: nfqnl_test.o
	g++ -o netfilter_block nfqnl_test.o -lnetfilter_queue

nfqnl_test.o: nfqnl_test.c
	g++ -c -o nfqnl_test.o nfqnl_test.c

clean:
	rm -f *.o netfilter_block

