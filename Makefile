PREFIX=/usr/local

all:
	mkdir -p bin
	$(CC) $(CFLAGS) -O3 -std=c11 -Wall -fstack-protector-strong *.c -o bin/massdns -ldl
debug:
	mkdir -p bin
	$(CC) $(CFLAGS) -O0 -std=c11 -Wall -g -DDEBUG *.c -o bin/massdns -ldl
install:
	test -d $(PREFIX) || mkdir $(PREFIX)
	test -d $(PREFIX)/bin || mkdir $(PREFIX)/bin
	install -m 0755 bin/massdns $(PREFIX)/bin
