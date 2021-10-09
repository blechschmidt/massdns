PREFIX=/usr/local
PROJECT_FLAGS=-DMASSDNS_REVISION=\"$(shell git describe --tags --dirty=+)\"

all:
	mkdir -p bin
	$(CC) $(CFLAGS) $(PROJECT_FLAGS) -O3 -std=c11 -DHAVE_EPOLL -DHAVE_SYSINFO -Wall -fstack-protector-strong src/main.c -o bin/massdns
debug:
	mkdir -p bin
	$(CC) $(CFLAGS) $(PROJECT_FLAGS) -O0 -std=c11 -DHAVE_EPOLL -DHAVE_SYSINFO -Wall -g -DDEBUG src/main.c -o bin/massdns
nolinux:
	mkdir -p bin
	$(CC) $(CFLAGS) $(PROJECT_FLAGS) -O3 -std=c11 -Wall -fstack-protector-strong src/main.c -o bin/massdns
debugnolinux:
	mkdir -p bin
	$(CC) $(CFLAGS) $(PROJECT_FLAGS) -O0 -std=c11 -Wall -fstack-protector-strong -g -DDEBUG src/main.c -o bin/massdns
install:
	test -d $(PREFIX) || mkdir $(PREFIX)
	test -d $(PREFIX)/bin || mkdir $(PREFIX)/bin
	install -m 0755 bin/massdns $(PREFIX)/bin
