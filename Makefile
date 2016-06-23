all:
	mkdir -p bin
	gcc -std=c11 -fstack-protector-strong *.c -o bin/massdns
debug:
	mkdir -p bin
	gcc -std=c11 -g -DDEBUG *.c -o bin/massdns
tests:
	mkdir -p bin
	gcc -std=c11 -g -DDEBUG -fstack-protector-strong tests/*.c -o bin/tests
