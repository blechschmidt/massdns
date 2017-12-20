#!/usr/bin/python

# Script for extracting potentially usable resolvers from the Censys scan at
# https://censys.io/data/53-dns-lookup-full_ipv4

import sys
import json

CENSYS_IP = "192.150.186.1"
QNAME = "c.afekv.com"

if len(sys.argv) < 2:
    print("Rapid7 DNS lookup file required as parameter")
    sys.exit(1)

with open(sys.argv[1], "r") as f:
    for line in f:
        data = json.loads(line)
        if data["success"] == 1 and data["dns_rcode"] == 0:
            if len(data["dns_answers"]) == 2 and \
                data["dns_answers"][0]["name"] == QNAME and \
                data["dns_answers"][1]["name"] == QNAME and \
                (data["dns_answers"][0]["rdata"] == CENSYS_IP or \
                data["dns_answers"][1]["rdata"] == CENSYS_IP):
                print(data["saddr"])
