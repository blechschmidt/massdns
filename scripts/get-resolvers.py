#!/usr/bin/env python3

import os
import requests
import validators
import json

NAMESERVERS_URL='https://public-dns.info/nameserver/nameservers.json'
MIN_RELIABILIY=0.99

try:
    # Fetch public servers
    r = requests.get(NAMESERVERS_URL)
    for ip in json.loads(r.text):
        # Only focus on reliable ipv4 addresses
        if validators.ipv4(ip['ip']) and ip['reliability'] > MIN_RELIABILIY:
            # Write results
            print(ip['ip'])

except Exception as e:
    print("Error fetching nameservers.")
