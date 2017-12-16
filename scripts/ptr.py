#!/usr/bin/python

# Print all possible IPv4 addresses
# May be useful for resolving PTR records via MassDNS /dev/stdin

from itertools import product

for a, b, c, d in product(range(256), repeat=4):
	print("%d.%d.%d.%d.in-addr.arpa" % (a, b, c, d))
