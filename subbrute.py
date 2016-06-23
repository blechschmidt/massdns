#!/usr/bin/env python

import sys

if len(sys.argv) < 3:
	print("Usage: %s <subdomains> <domain1> ... <domainN>" % sys.argv[0])

for lines in open(sys.argv[1]):
	for arg in sys.argv[2:]:
		if lines.strip() != "":
			print(lines.strip() + "." + arg)
