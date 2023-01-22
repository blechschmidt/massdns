#!/usr/bin/env python3

import argparse
import json
import sys
import os
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description='Certificate transparency name extractor.')
parser.add_argument('-d', '--domains', metavar='domain_file', type=str, help='File containing domains for certificate search.',
                    required=False)
parser.add_argument('domain', nargs='*', help='Domain for certificate search.')
args = parser.parse_intermixed_args()


def append_domain(lst, dom):
    stripped = dom.strip().strip('.')
    if stripped != '':
        lst.append(stripped)


domains = []
if args.domains:
    with open(args.domains) as f:
        for line in f:
            append_domain(domains, line)

for domain in args.domain:
    append_domain(domains, domain)

for arg in domains:
    subdomains = set()
    with urllib.request.urlopen('https://crt.sh/?output=json&q=' + urllib.parse.quote('%.' + arg)) as f:
        data = json.loads(f.read().decode('utf-8'))
        for crt in data:
            for domain in crt['name_value'].split('\n'):
                if '@' in domain:
                    continue
                if domain not in subdomains:
                    subdomains.add(domain)
                    try:
                        print(domain)
                    except BrokenPipeError:
                        # https://docs.python.org/3/library/signal.html#note-on-sigpipe
                        # Python flushes standard streams on exit; redirect remaining output
                        # to devnull to avoid another BrokenPipeError at shutdown
                        devnull = os.open(os.devnull, os.O_WRONLY)
                        os.dup2(devnull, sys.stdout.fileno())
                        sys.exit(1)  # Python exits with error code 1 on EPIPE
