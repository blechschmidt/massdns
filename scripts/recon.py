#!/usr/bin/python3

"""
Authoritative Subdomain Enumeration Tool.

This script performs subdomain enumeration against authoritative name servers directly and thus does not require third-
party resolvers. The concurrency is determined automatically by massdns and supports hundreds of thousands of queries
per second, while delivering reliable results.

Limitation: Zone delegation is only handled up to the delegation point. For example, if example.org is enumerated and
sub.example.org is delegated to another name server, abc.sub.example.org will not be found by this script if "abc.sub"
is contained in the word list. However, this script will report this fact as ?.sub.example.org in this case.

This script performs differential testing. It will therefore not only report those subdomains for which a DNS record of
the specified type (--type; A record by default) is found, but also include non-empty terminals or names for which
another record type might exist.

By default, the script performs wildcard detection in a second name resolution process. For example, if the script
detects the presence of abc.sub.example.org and xyz.sub.example.org, it will query <random_string>.sub.example.org and
compare the resulting records to those of abc.sub.example.org and xyz.sub.example.org.
"""

import argparse
import asyncio
import atexit
import json
import os.path
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import tempfile
from collections import OrderedDict
from typing import Optional

import dns.asyncresolver
import psutil
import tqdm

TEMP_PREFIX = 'massdns'
tempdir = None


def ip_supported(version):
    try:
        from pyroute2.iproute import IPRoute
    except ImportError:
        return version == 4
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    with IPRoute() as ip:
        routes = ip.route('dump', family=family)
        for route in routes:
            if route.get('dst_len') == 0 and route.get('table') == 254:
                return True
    return False


def random_subdomain(length=10):
    return ''.join([random.choice(string.ascii_lowercase) for _ in range(length)])


def is_descendant(name, parent, real_descendant=False):
    if isinstance(name, str):
        name = canonicalize(name)
    if isinstance(parent, str):
        parent = canonicalize(parent)
    required_length = len(parent)
    if real_descendant:
        required_length += 1
    return len(name) >= required_length and name[:len(parent)] == parent


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


async def get_ips(names, resolver=None, ipv6_only=False):
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()

    awaitables = []

    for name in names:
        if ip_supported(4) and not ipv6_only:
            awaitables.append(resolver.resolve(name, dns.rdatatype.A, raise_on_no_answer=False))
        if ip_supported(6) or ipv6_only:
            awaitables.append(resolver.resolve(name, dns.rdatatype.AAAA, raise_on_no_answer=False))

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
    return set(frozenset((k, v) for k, v in x.items() if k != 'name' and k != 'ttl') for x in section)


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
        self.iterators = [iter(h) for h in self.handles]
        self.file = 0
        return self

    def __next__(self):
        while True:
            it = self.iterators[self.file]
            try:
                line = next(it)
                break
            except StopIteration:
                self.iterators.remove(it)
                if len(self.iterators) == 0:
                    raise StopIteration
            finally:
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


class DnsNode:
    def __init__(self):
        self.children = {}
        self.hits = 0
        self.data = None
        self.delegation = False

    def add(self, name):
        self.hits += 1
        if isinstance(name, str):
            name = canonicalize(name)
            it = iter(name)
        elif isinstance(name, list):
            it = iter(name)
        else:
            it = name
        try:
            first_label = next(it)
        except StopIteration:
            return self
        if first_label not in self.children:
            self.children[first_label] = DnsNode()
        return self.children[first_label].add(it)

    def remove(self, name):
        if isinstance(name, str):
            name = canonicalize(name)
        parent = self.find(name[:-1])
        if parent is None:
            return False
        del parent.children[name[-1]]
        return True

    def find(self, name):
        if isinstance(name, str):
            name = canonicalize(name)
            it = iter(name)
        elif isinstance(name, list):
            it = iter(name)
        else:
            it = name
        try:
            first_label = next(it)
        except StopIteration:
            return self
        if first_label not in self.children:
            return None
        return self.children[first_label].find(it)

    def traverse(self):
        return self._traverse([])

    def _traverse(self, name):
        for child in self.children:
            new_name = name + [child]
            yield new_name, self.children[child]
            for c in self.children[child]._traverse(new_name):
                yield c

    def sort(self):
        for name, node in self.traverse():
            node.children = OrderedDict((key, node.children[key]) for key in sorted(node.children.keys()))


def massdns_show_progress(proc, total):
    last = 0
    processed = 0
    with tqdm.tqdm(total=total) as pbar:
        for line in proc.stderr:
            decoded = line.decode()
            try:
                loaded = json.loads(decoded)
                processed = loaded['processed_queries']
            except json.JSONDecodeError:
                sys.stdout.write(decoded)
            pbar.update(processed - last)
            last = processed
        pbar.update(total - processed)

    proc.wait()


def log(msg):
    sys.stderr.write(msg + '\n')


def canonicalize(name):
    return list(reversed(name.rstrip('.').split('.')))


def get_auth_server(auth, soa):
    soa = canonicalize(soa)
    result = None
    for record in auth:
        if record['type'] != 'NS':
            continue
        name = canonicalize(record['name'])
        if is_descendant(name, soa) and (result is None or len(name) < len(result)):
            result = name
    return result


async def main():
    global tempdir

    server_behavior = DnsServerBehavior()

    cpu_count = psutil.cpu_count(logical=False)

    parser = argparse.ArgumentParser(description='Authoritative Subdomain Enumeration Tool.')
    parser.add_argument('--domain', '-d', metavar='DOMAIN', help='Domain name.', required=True)
    parser.add_argument('--wordlist', '-l', metavar='WORDLIST', help='Subdomain wordlist file.', required=True)
    parser.add_argument('--type', '-t', metavar='RTYPE', help='DNS record type to test against.', default='A')
    parser.add_argument('--skip-avail-check', help='Do not test whether nameservers are available.',
                        action='store_true')
    parser.add_argument('--no-wildcard-filter', help='Do not filter replies that appear to be wildcard responses.',
                        action='store_true')
    parser.add_argument('--wildcard-threshold', help='Wildcard check threshold.', type=int, default=2)
    parser.add_argument('--massdns', help='Path to massdns binary.')
    parser.add_argument('--concurrency', '-s', help='MassDNS concurrency.', default='auto')
    parser.add_argument('--interval', '-i', help='MassDNS resolution timeout.', default='500')
    parser.add_argument('--resolve-count', '-c', help='MassDNS resolution count.', default='50')
    parser.add_argument('--outfile', '-w', help='Store results in file instead of printing to stdout')
    parser.add_argument('--format', '-f', help='Output format', choices=['list', 'json'], default='list')
    args = parser.parse_args()
    domain = args.domain.encode('idna').decode('ascii').rstrip('.')
    domain_labels = domain.split('.')

    if not re.match(r'^[a-zA-Z0-9_-][a-zA-Z0-9_.-]+$', domain):
        log('Invalid domain.')
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
        log('SOA for %s: %s' % (domain, soa))
        nameservers = list(map(lambda ns: ns.rstrip('.'), await get_ns_names(soa)))
        log(domain + ' nameservers: %s' % ', '.join(nameservers))
        nameserver_ips = await get_ips(nameservers)
        log(domain + ' nameserver IP addresses: %s' % ', '.join(nameserver_ips))

        if not args.skip_avail_check:
            working_ns = set(await working_servers(domain, nameserver_ips))
            non_working = set(nameserver_ips) - working_ns
            if len(non_working) == 0:
                log('All nameservers are up.')
            else:
                log('Some nameservers are down: %s' % ', '.join(non_working))
            nameserver_ips = list(working_ns)

        resolver_file_contents = '\n'.join(nameserver_ips)
        resolvers_file.write(resolver_file_contents)

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = nameserver_ips
    wildcard_test_name = (random_subdomain() + '.' + domain).lower()

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
    log('The nameserver ' + predicate + ' NOERROR for non-existing domains.')

    log('Writing enumeration input file ...')
    total = 1
    with open(wordlist_path) as wordlist_file, open(permutations_path, 'w') as permutations_file:
        permutations_file.write(wildcard_test_name + '\n')
        for line in wordlist_file:
            subdomain = line.strip()
            if subdomain == '':
                continue
            if not subdomain.endswith('.'):
                subdomain += '.'
            permutations_file.write((subdomain + domain).lower() + '\n')
            total += 1

    log('MassDNS enumeration ...')

    massdns_args = [
        '-s', args.concurrency,
        '-i', args.interval,
        '-c', args.resolve_count
    ]
    output_flags = ['Je', '--filter', 'NOERROR'] if not server_behavior.global_noerror else ['Je']
    proc = subprocess.Popen([massdns_path,
                             '-o', *output_flags,
                             '--retry', 'never',
                             '-r', resolvers_path,
                             '-w', output_path,
                             '--status-format', 'json',
                             '--processes', str(cpu_count),
                             '-t', args.type,
                             *massdns_args,
                             permutations_path], stderr=subprocess.PIPE)

    massdns_show_progress(proc, total)

    def filter_answers(_):
        return False

    log('Output processing ...')

    errors_seen = False
    if cpu_count <= 1:
        massdns_outfiles = [output_path]
    else:
        massdns_outfiles = [output_path + str(i) for i in range(0, cpu_count)]
    with MultiFileLineReader(massdns_outfiles) as f:
        if not args.no_wildcard_filter and server_behavior.global_noerror:
            for line in f:
                parsed = json.loads(line)
                if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                    answers = parsed.get('data', {}).get('answers', [])

                    def func(compare):
                        def f(section):
                            cmp = create_rrset(section)
                            return compare == cmp

                        return f

                    filter_answers = func(create_rrset(answers))

                    break

    dns_tree = DnsNode()

    with MultiFileLineReader(massdns_outfiles) as f:
        for line in f:
            parsed = json.loads(line)
            if parsed['name'].rstrip('.') == wildcard_test_name.rstrip('.'):
                continue
            if 'data' in parsed:
                data = parsed['data']
                authorities = data.get('authorities', [])
                answers = data.get('answers', [])

                if filter_answers(answers):
                    continue

                # In the case of zone delegation, we mark the delegated node in the DNS tree
                if 'aa' not in parsed['flags'] and parsed['status'] == 'NOERROR':
                    auth_server = get_auth_server(authorities, soa)
                    if auth_server is not None and is_descendant(parsed['name'], auth_server):
                        added = dns_tree.add(auth_server)
                        added.data = parsed
                        added.delegation = True
                        continue

                added = dns_tree.add(parsed['name'])
                added.data = parsed
            elif 'error' in parsed:
                if not errors_seen:
                    errors_seen = True
                    sys.stderr.write('Resolving the following names failed:\n')
                sys.stderr.write(parsed['name'].rstrip('.') + '\n')

    if not args.no_wildcard_filter:
        log('Writing wildcard test input file ...')

        wildcard_subdomain1 = random_subdomain()
        wildcard_subdomain2 = random_subdomain()
        wildcard_check = DnsNode()
        wildcard_in_path = os.path.join(tempdir, 'wildcard_in')
        total = 0
        with open(wildcard_in_path, 'w') as wildcard_file:
            for name, node in dns_tree.traverse():
                if len(name) <= len(domain_labels):
                    continue
                if node.hits > args.wildcard_threshold and not node.delegation:
                    normalized = '.'.join(reversed(name))
                    wildcard_check.add(normalized).data = node.data
                    wildcard_file.write(wildcard_subdomain1 + '.' + normalized + '\n' +
                                        wildcard_subdomain2 + '.' + normalized + '\n')
                    total += 2

        wildcard_out_path = os.path.join(tempdir, 'wildcard_out')

        proc = subprocess.Popen([massdns_path,
                                 '-o', 'Je',
                                 '--retry', 'never',
                                 '-r', resolvers_path,
                                 '-w', wildcard_out_path,
                                 '--status-format', 'json',
                                 '--processes', str(cpu_count),
                                 '-t', args.type,
                                 *massdns_args,
                                 wildcard_in_path], stderr=subprocess.PIPE)

        massdns_show_progress(proc, total)

        if cpu_count <= 1:
            wildcard_out_paths = [wildcard_out_path]
        else:
            wildcard_out_paths = [wildcard_out_path + str(i) for i in range(0, cpu_count)]
        wildcard_cmp = {}
        with MultiFileLineReader(wildcard_out_paths) as f:
            for line in f:
                parsed = json.loads(line)
                answers = create_rrset(parsed.get('data', {}).get('answers', []))
                name = canonicalize(parsed['name'])[:-1]

                node = dns_tree.find(name)
                if node is None:
                    continue

                # We use two random strings to filter random records.
                # As an example, <random1>.sandbox.google.com differs from <random2>.sandbox.google.com.
                # This means that we cannot infer something useful from differing records below sandbox.google.com.
                # We treat it as a wildcard then.
                hashable_name = '.'.join(name)
                if hashable_name not in wildcard_cmp:
                    wildcard_cmp[hashable_name] = parsed
                elif parsed['status'] != wildcard_cmp[hashable_name]['status'] or \
                        create_rrset(wildcard_cmp[hashable_name].get('data', {}).get('answers', [])) != answers:
                    child = DnsNode()
                    child.data = parsed
                    node.children = {'*': child}
                    continue

                # Remove those nodes whose records are equal to the wildcard's records
                erase = []
                for subdomain, child in node.traverse():
                    if child.data is None:
                        continue
                    answers_cmp = create_rrset(child.data.get('data', {}).get('answers', []))
                    if answers == answers_cmp and parsed['status'] == child.data['status']:
                        erase.append(subdomain)
                for n in erase:
                    node.remove(n)

                if parsed['status'] == 'NOERROR':
                    child = DnsNode()
                    child.data = parsed
                    node.children['*'] = child

    dns_tree.sort()
    f = sys.stdout if args.outfile is None else open(args.outfile, 'w')
    try:
        for name, node in dns_tree.traverse():
            if len(name) <= len(domain_labels):
                continue
            print_name = '.'.join(reversed(name))
            if node.delegation:
                print_name = '?.' + print_name
            if args.format == 'list':
                f.write(print_name + '\n')
            else:
                obj = {
                    'name': print_name,
                    'query': node.data
                }
                f.write(json.dumps(obj) + '\n')
    finally:
        if args.outfile is not None:
            f.close()


asyncio.run(main())
