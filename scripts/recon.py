#!/usr/bin/python3

"""
Authoritative Subdomain Enumeration Tool.

This script performs subdomain enumeration against authoritative name servers directly and thus does not require third-
party resolvers. The concurrency is determined automatically by massdns.
"""

import argparse
import asyncio
import atexit
import json
import os.path
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
from typing import Optional

import dns.asyncresolver
import psutil
import tqdm

TEMP_PREFIX = 'massdns'
tempdir = None


def random_subdomain(length=10):
    return ''.join([random.choice(string.ascii_lowercase) for _ in range(length)])


def extract_record_data(answer):
    result = []
    for data in answer.response.answer:
        for value in data:
            result.append(str(value))
    return result


async def get_soa(name, resolver=None):
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
    result = await resolver.resolve(name, dns.rdatatype.SOA, raise_on_no_answer=False)
    for record in result.response.answer + result.response.authority:
        if record.rdtype == dns.rdatatype.SOA:
            return str(record.name)


async def get_ns_names(name, resolver=None, detect_soa=True):
    if not name.endswith('.'):
        name += '.'
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
    result = await resolver.resolve(name, dns.rdatatype.NS, raise_on_no_answer=False)
    if detect_soa:
        for record in result.response.authority:
            if record.rdtype == dns.rdatatype.SOA:
                return await get_ns_names(str(record.name), resolver, detect_soa=False)
    return extract_record_data(result)


async def get_ips(names, resolver=None):
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()

    awaitables = []
    for name in names:
        awaitables.append(resolver.resolve(name, dns.rdatatype.A))

    result = []
    for answer in await asyncio.gather(*awaitables):
        result += extract_record_data(answer)
    return list(set(result))


def massdns_find_path():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    massdns_git_path = os.path.realpath(os.path.join(script_dir, '..', 'bin', 'massdns'))
    if os.access(massdns_git_path, os.F_OK | os.X_OK):
        return massdns_git_path

    massdns_in_path = shutil.which('massdns')
    if massdns_in_path is not None:
        return massdns_in_path


def create_rrset(section):
    return set(frozenset((k, v) for k, v in x.items() if k != 'name') for x in section)


async def working_servers(qname, nameserver_ips):
    nameserver_ips = list(nameserver_ips)
    good_codes = {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}

    tasks = []
    for nameserver in nameserver_ips:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [nameserver]
        tasks.append(resolver.resolve(qname, raise_on_no_answer=False))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    working_ips = []
    for i, ip in enumerate(nameserver_ips):
        if isinstance(results[i], dns.resolver.Answer) and results[i].response.rcode() in good_codes:
            working_ips.append(ip)
    return working_ips


class MultiFileLineReader:
    def __init__(self, files):
        self.files = files
        self.handles = []

    def __iter__(self):
        self.iterators = [h.__iter__() for h in self.handles]
        self.file = 0
        return self

    def __next__(self):
        line = self.iterators[self.file].__next__()
        self.file += 1
        if self.file >= len(self.iterators):
            self.file = 0
        return line

    def __enter__(self):
        self.handles = [open(file) for file in self.files]
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for handle in self.handles:
            handle.close()


class DnsServerBehavior:
    global_noerror: Optional[bool] = None  # Whether the server returns NOERROR for non-existing names


async def main():
    global tempdir

    server_behavior = DnsServerBehavior()

    cpu_count = psutil.cpu_count(logical=False)

    parser = argparse.ArgumentParser(description='Authoritative Subdomain Enumeration Tool.')
    parser.add_argument('--domain', '-d', metavar='DOMAIN', help='Domain name.', required=True)
    parser.add_argument('--wordlist', '-w', metavar='WORDLIST', help='Subdomain wordlist file.', required=True)
    parser.add_argument('--skip-avail-check', help='Do not test whether nameservers are available.',
                        action='store_true')
    parser.add_argument('--no-wildcard-filter', help='Do not filter replies that appear to be wildcard responses.',
                        action='store_true')
    parser.add_argument('--massdns', help='Path to massdns binary.')
    args = parser.parse_args()
    domain = args.domain.encode('idna').decode('ascii')

    if not re.match(r'^[a-zA-Z0-9_-][a-zA-Z0-9_.-]+$', domain):
        sys.stderr.write('Invalid domain.\n')
        sys.exit(1)

    massdns_path = massdns_find_path() if args.massdns is None else args.massdns
    if massdns_path is None:
        sys.stderr.write('MassDNS binary not found.\n')
        sys.exit(1)

    tempdir = tempfile.mkdtemp(prefix=TEMP_PREFIX + '_' + domain + '_')
    atexit.register(lambda: shutil.rmtree(tempdir, ignore_errors=True))
    resolvers_path = os.path.join(tempdir, 'resolvers')
    permutations_path = os.path.join(tempdir, 'permutations')
    output_path = os.path.join(tempdir, 'output')
    wordlist_path = args.wordlist

    with open(resolvers_path, 'w') as resolvers_file:
        soa = await get_soa(domain)
        sys.stderr.write('SOA for %s: %s\n' % (domain, soa))
        nameservers = list(map(lambda ns: ns.rstrip('.'), await get_ns_names(soa)))
        sys.stderr.write(domain + ' nameservers: %s\n' % ', '.join(nameservers))
        nameserver_ips = await get_ips(nameservers)
        sys.stderr.write(domain + ' nameserver IP addresses: %s\n' % ', '.join(nameserver_ips))

        if not args.skip_avail_check:
            working_ns = set(await working_servers(domain, nameserver_ips))
            non_working = set(nameserver_ips) - working_ns
            if len(non_working) == 0:
                sys.stderr.write('All nameservers are up.\n')
            else:
                sys.stderr.write('Some nameservers are down: %s\n' % ', '.join(non_working))
            nameserver_ips = list(working_ns)

        resolver_file_contents = '\n'.join(nameserver_ips)
        resolvers_file.write(resolver_file_contents)

    wildcard_test_name = (random_subdomain() + '.' + domain).lower()
    with open(wordlist_path) as wordlist_file, open(permutations_path, 'w') as permutations_file:
        permutations_file.write(wildcard_test_name + '\n')
        for line in wordlist_file:
            subdomain = line.strip()
            if subdomain == '':
                continue
            if not subdomain.endswith('.'):
                subdomain += '.'
            permutations_file.write((subdomain + domain).lower() + '\n')

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = nameserver_ips

    """In case the server returns NXDOMAIN for non-existing names, another rcode is a strong indicator for another
    type of record existing for a name. (For example, if `A random-subdomain.example.com` returns NXDOMAIN while
    `A mail.example.com` returns NOERROR, it may be because `MX mail.example.com` exists.)"""
    try:
        answer = await resolver.resolve(wildcard_test_name, raise_on_no_answer=False)
        rcode = answer.response.rcode()
        server_behavior.global_noerror = rcode == dns.rcode.NOERROR
    except dns.resolver.NXDOMAIN:
        server_behavior.global_noerror = False
    predicate = 'returns' if server_behavior.global_noerror else 'does not return'
    sys.stderr.write('The nameserver ' + predicate + ' NOERROR for non-existing domains.\n')

    output_flags = ['Je', '--filter', 'NOERROR'] if not server_behavior.global_noerror else ['Je']
    proc = subprocess.Popen([massdns_path, '-o', *output_flags, '-s', 'auto', '--retry', 'never', '-r', resolvers_path,
                             '-w', output_path, '--status-format', 'json', '--processes', str(cpu_count),
                             permutations_path], stderr=subprocess.PIPE)
    last = 0
    with tqdm.tqdm(total=100) as pbar:
        for line in proc.stderr:
            decoded = line.decode()
            try:
                percent = json.loads(decoded)['progress']['percent']
            except json.JSONDecodeError:
                sys.stdout.write(decoded)
            pbar.update(percent - last)
            last = percent

    proc.wait()

    def filter_answers(_):
        return False

    def filter_authorities(_):
        return False

    errors_seen = False
    # TODO: Improve performance by piping stdout and returning matching results immediately instead of using a temp file
    with MultiFileLineReader([output_path + str(i) for i in range(0, cpu_count)]) as f:
        if not args.no_wildcard_filter and server_behavior.global_noerror:
            for line in f:
                parsed = json.loads(line)
                if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                    answers = parsed.get('data', {}).get('answers', [])
                    authorities = parsed.get('data', {}).get('authorities', [])

                    def func(compare):
                        def filter(section):
                            cmp = set(frozenset((k, v) for k, v in x.items() if k != 'name') for x in section)
                            return compare == cmp

                        return filter

                    filter_answers = func(create_rrset(answers))
                    filter_authorities = func(create_rrset(authorities))

                    break

    with MultiFileLineReader([output_path + str(i) for i in range(0, cpu_count)]) as f:
        for line in f:
            parsed = json.loads(line)
            if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                continue
            if 'data' in parsed:
                data = parsed['data']
                authorities = data.get('authorities', [])
                answers = data.get('answers', [])

                if filter_answers(answers) and filter_authorities(authorities):
                    continue
                print(parsed['name'].rstrip('.'))
            elif 'error' in parsed:
                if not errors_seen:
                    errors_seen = True
                    sys.stderr.write('Resolving the following names failed:\n')
                sys.stderr.write(parsed['name'].rstrip('.') + '\n')


asyncio.run(main())
