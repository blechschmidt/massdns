#!/usr/bin/env python3

import sys
import urllib.request
import urllib.parse
import json


if len(sys.argv) == 1:
	print("Usage: " + sys.argv[0] + " [domain] ...")
	sys.exit(1)

for i, arg in enumerate(sys.argv, 1):
	domains = set()
	with urllib.request.urlopen('https://crt.sh/?output=json&q=' + urllib.parse.quote('%.' + arg)) as f:
		data = json.loads(f.read().decode('utf-8'))
		for crt in data:
			for domain in crt['name_value'].split('\n'):
				if not domain in domains:
					domains.add(domain)
					print(domain)
