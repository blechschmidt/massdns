PREFIX=/usr/local

all:
	mkdir -p bin
	$(CC) $(CFLAGS) -O3 -std=c11 -DHAVE_EPOLL -DHAVE_SYSINFO -Wall -fstack-protector-strong main.c -o bin/massdns
debug:
	mkdir -p bin
	$(CC) $(CFLAGS) -O0 -std=c11 -DHAVE_EPOLL -DHAVE_SYSINFO -Wall -g -DDEBUG main.c -o bin/massdns
nolinux:
	mkdir -p bin
	$(CC) $(CFLAGS) -O3 -std=c11 -Wall -fstack-protector-strong main.c -o bin/massdns
install:
	test -d $(PREFIX) || mkdir $(PREFIX)
	test -d $(PREFIX)/bin || mkdir $(PREFIX)/bin
	install -m 0755 bin/massdns $(PREFIX)/bin
