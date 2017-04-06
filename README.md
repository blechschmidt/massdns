# MassDNS 0.2
## A high-performance DNS stub resolver

MassDNS is a simple high-performance DNS stub resolver targetting those who seek to resolve a massive amount of domain names in the order of millions or even billions.
Without special configuration, MassDNS is capable of resolving over 100,000,000 domains per hour with a Gigabit ethernet link using publicly available resolvers.

## Contributors
* [Quirin Scheitle](https://github.com/quirins), [Technical University of Munich](https://www.net.in.tum.de/members/scheitle/)

## Requirements
MassDNS requires [ldns](https://www.nlnetlabs.nl/projects/ldns/). It can be installed using `apt-get install libldns-dev` on Debian or Ubuntu.

## Compilation
Clone the git repository and `cd` into the project root folder. Then run `make` to build from source.

## Usage
```
Usage: ./bin/massdns [options] domainlist (- for stdin) 
  -a  --no-authority     Omit records from the authority section of the response packets.
  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)
  -e  --additional       Include response records within the additional section.
  -h  --help             Show this help.
  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same domain. (Default: 200)
  -m  --module           Load a shared module in order to handle packets.
  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.
  -o  --only-responses   Do not output DNS questions.
  -p  --progress         Show the progress and remaining time.
  -q  --quiet            Quiet mode.
  -r  --resolvers        Text file containing DNS resolvers.
      --root             Allow running the program as root. Not recommended.
  -s  --hashmap-size     Set the size of the hashmap used for resolving. (Default: 100000)
  -t  --type             Record type to be resolved. (Default: A)
  -w  --outfile          Write to the specified output file instead of standard output.

Supported record types:
  A
  AAAA
  ANY
  CNAME
  DNAME
  MX
  NS
  PTR
  SOA
  TXT
  CAA
  TLSA
```
By default, MassDNS will print status information on standard error, results are written to stdout.

### Example
Resolve all AAAA records from domains within domains.txt using the resolvers within resolvers.txt and store the results within results.txt:
```
$ ./bin/massdns -r resolvers.txt -t AAAA example.txt > results.txt
```

This is equivalent to:
```
$ ./bin/massdns -r resolvers.txt -t AAAA -w results.txt example.txt
```

#### Example output
By default, MassDNS will output response packets in text format which looks similar to the following:
```
193.200.68.230:53 1466115053 NOERROR example.com. IN AAAA   # resolver, Unix timestamp, query name, class, record
    example.com. 21479 IN AAAA 2606:2800:220::1     # name, TTL, class, record, record data
                                                    # empty line separates answer and authority records 
    example.com. 21200 IN NS a.iana-servers.net.    # name, TTL, class, record, record data
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
```
$ ./ptr.py | ./bin/massdns -r resolvers.txt -t PTR -w ptr.txt -
```
Please note that the labels within `in-addr.arpa` are reversed. In order to resolve the domain name of `1.2.3.4`, MassDNS expects `4.3.2.1.in-addr.arpa` as input query name.
As a consequence, the Python script does not resolve the records in an ascending order which is an advantage because sudden heavy spikes at the name servers of IPv4 subnets are avoided.

#### Brute-forcing subdomains
Similar to [subbrute](https://github.com/TheRook/subbrute), MassDNS allows you to brute force subdomains using the included `subbrute.py` script:
```
$ ./subbrute.py names.txt example.com | ./bin/massdns -r resolvers.txt -t A -a -o -w results.txt -
```

The files `names.txt` and `names_small.txt`, which have been copied from the [subbrute project](https://github.com/TheRook/subbrute), contain names of commonly used subdomains.

## Screenshots
![Screenshot](https://www.cysec.biz/projects/massdns/screenshots/screenshot1.png)

## Security
MassDNS does not require root privileges and will therefore drop privileges to the user called "nobody" by default when being run as root.
If the user "nobody" does not exist, MassDNS will refuse execution. In this case, it is recommended to run MassDNS as another non-privileged user.
The privilege drop can be circumvented using the `--root` argument which is not recommended.
Also note that other branches than master should not be used in production at all.

## Development
MassDNS supports the development of minimalistic custom modules. An example module supporting binary output can be found within the folder `modules`.
The example module has to be built separately by running `make`.
Please note that the module interfaces are not stable yet and are subject to change during further development of MassDNS.

## Todo
- Prevent flooding resolvers which are employing rate limits or refusing resolves after some time
- Implement bandwidth limits
- Employ cross-resolver checks to detect DNS poisoning and DNS spam (e.g. [Level 3 DNS hijacking](https://web.archive.org/web/20140302064622/http://james.bertelson.me/blog/2014/01/level-3-are-now-hijacking-failed-dns-requests-for-ad-revenue-on-4-2-2-x/))
- Implement IO-multiplexing to prevent 100% usage of a single CPU core
- Support IPv6 resolvers
