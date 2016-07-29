all:
	mkdir -p bin
	$(CC) -std=c11 -Wall -fstack-protector-strong *.c -o bin/massdns -lldns
debug:
	mkdir -p bin
	$(CC) -std=c11 -Wall -g -DDEBUG *.c -o bin/massdns -lldns
