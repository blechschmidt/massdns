#!/usr/bin/python3

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


async def get_ns_names(name, resolver=None):
    if not name.endswith('.'):
        name += '.'
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
    answer = await resolver.resolve(name, dns.rdatatype.NS)
    return extract_record_data(answer)


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


async def working_servers(qname, nameserver_ips):
    good_codes = {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}

    tasks = []
    for nameserver in nameserver_ips:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [nameserver]
        tasks.append(resolver.resolve(qname))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    working_ips = []
    for i, ip in enumerate(nameserver_ips):
        if isinstance(results[i], dns.resolver.Answer) and results[i].response.rcode() in good_codes:
            working_ips.append(ip)
    return working_ips


class DnsServerBehavior:
    global_noerror: Optional[bool] = None  # Whether the server returns NOERROR for non-existing names


async def main():
    global tempdir

    server_behavior = DnsServerBehavior()

    parser = argparse.ArgumentParser(description='Authoritative subdomain enumeration tool.')
    parser.add_argument('--domain', '-d', metavar='DOMAIN', help='Domain name.', required=True)
    parser.add_argument('--wordlist', '-w', metavar='WORDLIST', help='Subdomain wordlist file.', required=True)
    parser.add_argument('--skip-avail-check', help='Do not test whether nameservers are available.',
                        action='store_true')
    parser.add_argument('--no-referrals-only', help='Do not return records that refer to another nameserver only.',
                        action='store_true')
    parser.add_argument('--no-wildcard-filter', help='Do not filter replies that appear to be wildcard responses.',
                        action='store_true')
    args = parser.parse_args()
    domain = args.domain.encode('idna').decode('ascii')

    if not re.match(r'^[a-zA-Z0-9_-][a-zA-Z0-9_.-]+$', domain):
        sys.stderr.write('Invalid domain.\n')
        sys.exit(1)

    massdns_path = massdns_find_path()
    if massdns_path is None:
        sys.stderr.write('MassDNS binary not found. Please specify its path manually.\n')
        sys.exit(1)

    tempdir = tempfile.mkdtemp(prefix=TEMP_PREFIX + '_' + domain + '_')
    atexit.register(lambda: shutil.rmtree(tempdir, ignore_errors=True))
    resolvers_path = os.path.join(tempdir, 'resolvers')
    permutations_path = os.path.join(tempdir, 'permutations')
    output_path = os.path.join(tempdir, 'output')
    wordlist_path = args.wordlist

    with open(resolvers_path, 'w') as resolvers_file:
        nameservers = list(map(lambda ns: ns.rstrip('.'), await get_ns_names(domain)))
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

    output_flags = ['Je', '--filter', 'NOERROR'] if not server_behavior.global_noerror else ['Jea']
    proc = subprocess.Popen([massdns_path, '-o', *output_flags, '-s', 'auto', '--retry', 'never', '-r', resolvers_path,
                             '-w', output_path, '--status-format', 'json', permutations_path], stderr=subprocess.PIPE)
    last = 0
    with tqdm.tqdm(total=100) as pbar:
        for line in proc.stderr:
            percent = json.loads(line.decode())['progress']['percent']
            pbar.update(percent - last)
            last = percent

    errors_seen = False
    # TODO: Improve performance by piping stdout and returning matching results immediately instead of using a temp file
    with open(output_path, 'r') as f:
        def filter_response(_):
            return False

        if not args.no_wildcard_filter:
            for line in f:
                parsed = json.loads(line)
                if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                    if 'data' not in parsed:
                        break
                    data = parsed['data']
                    answers = data.get('answers', [])
                    if answers == 0:
                        break
                    compare = set(frozenset((k, v) for k, v in x.items() if k != 'name') for x in data.get('answers'))

                    def filter_response(answ):
                        cmp = set(frozenset((k, v) for k, v in x.items() if k != 'name') for x in answ)
                        return compare == cmp

                break
            f.seek(0)

        for line in f:
            parsed = json.loads(line)
            if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                continue
            if 'data' in parsed:
                data = parsed['data']
                authorities = data.get('authorities', [])
                answers = data.get('answers', [])

                has_answers = len(answers) > 0
                has_referrals = any([auth['type'] == 'NS' and auth['name'] == parsed['name'] for auth in authorities])
                unlike_wildcard = not server_behavior.global_noerror and parsed.get('status', '') == 'NOERROR'
                if has_answers or (has_referrals and not args.no_referrals_only) or unlike_wildcard:
                    if filter_response(answers):
                        continue
                    print(parsed['name'].rstrip('.'))
            elif 'error' in parsed:
                if not errors_seen:
                    errors_seen = True
                    sys.stderr.write('Resolving the following names failed:\n')
                sys.stderr.write(parsed['name'].rstrip('.') + '\n')


asyncio.run(main())
