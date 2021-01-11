#!/usr/bin/env python3

import os
import requests
import validators
import json

NAMESERVERS_URL='https://public-dns.info/nameserver/nameservers.json'
OUTPUT_FILE=os.path.dirname(os.path.realpath(__file__)) + "/../lists/public-dns.txt"
MIN_RELIABILIY=0.99

try:

    # Try to open output file for writing
    with open(OUTPUT_FILE, 'w') as f:
        # Fetch public servers
        r = requests.get(NAMESERVERS_URL)
        for ip in json.loads(r.text):
            # Only focus on reliable ipv4 addresses
            if validators.ipv4(ip['ip']) and ip['reliability'] > MIN_RELIABILIY:
                # Write results
                f.write("%s\n" % ip['ip'])

except Exception as e:
    print("Error.")
