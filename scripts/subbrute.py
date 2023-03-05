#!/usr/bin/env python3

import argparse
import os
import sys

parser = argparse.ArgumentParser(description='Subdomain enumeration list generator.')
parser.add_argument('domain', nargs='*', help='Domain to append.')
parser.add_argument('subdomain_file', type=str, help='Subdomain file to append to.')
parser.add_argument('-d', '--domains', metavar='domain_file', type=str, help='File containing domains to append.',
                    required=False)
args = parser.parse_intermixed_args()

if not args.domain and not args.domains:
    sys.stderr.write('Either a domain file is required or domains have to be specified as additional arguments.\n')
    sys.exit(1)


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

with open(args.subdomain_file) as f:
    for line in f:
        subdomain = line.strip().strip('.')
        if subdomain == '':
            continue
        for domain in domains:
            try:
                print(subdomain + '.' + domain)
            except BrokenPipeError:
                # https://docs.python.org/3/library/signal.html#note-on-sigpipe
                # Python flushes standard streams on exit; redirect remaining output
                # to devnull to avoid another BrokenPipeError at shutdown
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                sys.exit(1)  # Python exits with error code 1 on EPIPE
