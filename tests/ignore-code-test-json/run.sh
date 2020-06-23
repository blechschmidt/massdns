#!/bin/bash

DIR=$(dirname "$0")
"$DIR"/../../bin/massdns -c 3 --quiet -r "$DIR"/google-dns.txt -o J --ignore NOERROR "$DIR"/names.txt | jq .name | grep -q -E "domain.invalid" && "$DIR"/../../bin/massdns -c 3 --quiet -r "$DIR"/google-dns.txt -o J --ignore NXDOMAIN "$DIR"/names.txt | jq .name | grep -q -E "google.com"
