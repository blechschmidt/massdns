all:
	mkdir -p bin
	$(CC) -std=c11 -fstack-protector-strong *.c -o bin/massdns -lldns
debug:
	mkdir -p bin
	$(CC) -std=c11 -g -DDEBUG *.c -o bin/massdns -lldns
