# MassDNS 0.1
## A high-performance DNS stub resolver

MassDNS is a simple high-performance DNS stub resolver targetting those who seek to resolve a massive amount of domain names in the order of millions or even billions.
Without special configuration, MassDNS is capable of resolving over 100,000,000 domains per hour with a Gigabit ethernet link using publicly available resolvers.

## Compilation
Clone the git repository and `cd` into the project root folder. Then run `make` to build from source.

## Usage
```
Usage: ./bin/massdns [options] domainlist
  -a  --no-authority     Omit records from the authority section of the response packets.
  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)
  -h  --help             Show this help.
  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same domain. (Default: 200)
  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.
  -o  --only-responses   Do not output DNS questions.
  -r  --resolvers        Text file containing DNS resolvers.
      --root             Allow running the program as root. Not recommended.
  -s  --hashmap-size     Set the size of the hashmap used for resolving. (Default: 500000)
  -t  --type             Record type to be resolved. (Default: A)
  -u  --unknown-records  Include unknown/unimplemented DNS records.

Supported record types:
  A
  AAAA
  ANY
  CNAME
  DNAME
  MX
  NS
  PTR
  TXT
```
By default, MassDNS will print status information on standard error, results are written to stdout. In order to store results, it is therefore recommended to use output redirection.

### Example
Resolve all A records from domains within domains.txt using the resolvers within resolvers.txt and store the results within results.txt:
```
$ ./bin/massdns -r resolvers.txt -t AAAA example.txt > results.txt
```

#### Example output
Currently, MassDNS only supports output in text format which looks similar to the following:
```
193.200.68.230 example.com IN AAAA 1466115053   # resolver, query name, class, record, Unix timestamp
    example.com 21479 IN AAAA 2606:2800:220::1  # name, TTL, class, record, record data
                                                # empty line separates answer and authority records 
    example.com 21200 IN NS a.iana-servers.net  # name, TTL, class, record, record data
                                                # ...
```

The resolver IP address is included in order to make it easier for you to filter the output in case you detect that some resolvers produce bad results.

### Resolving
The repository includes the file `resolvers.txt` consisting of a filtered subset of the resolvers provided by the [subbrute project](https://github.com/TheRook/subbrute).
Please note that the usage of MassDNS may cause a significant load on the used resolvers and result in abuse complaints being sent to your ISP.
Also note that the provided resolvers are not guaranteed to be trustworthy. If you detect a bad resolver that is still included within MassDNS, please file an issue.

MassDNS's DNS implementation is currently very sporadic and only supports the most common records. You are welcome to help changing this by collaborating.

#### PTR records
MassDNS includes a Python script allowing you to resolve all IPv4 PTR records by printing their respective queries to the standard output.
MassDNS does not yet support reading from stdin, which is why bash process substitution is the most convenient way to use this feature.
```
$ ./bin/massdns -r resolvers.txt -t PTR <(./ptr.py) > ptr.txt
```
Please note that the labels within `in-addr.arpa` are reversed. In order to resolve the domain name of `1.2.3.4`, MassDNS expects `4.3.2.1.in-addr.arpa` as input query name.
As a consequence, the Python script does not resolve the records in an ascending order which is an advantage because sudden heavy spikes at the name servers of IPv4 subnets are avoided.

#### Brute-forcing subdomains
Similar to [subbrute](https://github.com/TheRook/subbrute), MassScan allows you to brute force subdomains using the included `subbrute.py` script:
```
$ ./bin/massdns -r resolvers.txt -t A -a -o <(./subbrute.py names.txt example.com) > example.com_subdomains
```

The files `names.txt` and `names_small.txt`, which have been copied from the [subbrute project](https://github.com/TheRook/subbrute), contain names of commonly used subdomains.

## Screenshots
![Screenshot](https://www.cysec.biz/projects/massdns/screenshots/screenshot1.png)

## Security
MassDNS does not require root privileges and will therefore drop privileges to the user called "nobody" by default when being run as root.
If the user "nobody" does not exist, MassDNS will refuse execution. In this case, it is recommended to run MassDNS as another non-privileged user.
The privilege drop can be circumvented using the `--root` argument which is not recommended.

## Todo
- Prevent flooding resolvers which are employing rate limits or refusing resolves after some time
- Implement bandwidth limits
- Employ cross-resolver checks to detect DNS poisoning and DNS spam (e.g. [Level 3 DNS hijacking](https://web.archive.org/web/20140302064622/http://james.bertelson.me/blog/2014/01/level-3-are-now-hijacking-failed-dns-requests-for-ad-revenue-on-4-2-2-x/))
- Implement IO-multiplexing to prevent 100% usage of a single CPU core
- Improve, complete, extend, split up and/or replace the DNS library (e.g. [libldns](https://www.nlnetlabs.nl/projects/ldns/))
- Allow for the integration of dynamic libraries
- Implement additional (binary) output formats
