all:
	mkdir -p bin
	$(CC) $(CFLAGS) -std=c11 -Wall -fstack-protector-strong *.c -o bin/massdns -lldns -ldl
debug:
	mkdir -p bin
	$(CC) $(CFLAGS) -std=c11 -Wall -g -DDEBUG *.c -o bin/massdns -lldns -ldl
