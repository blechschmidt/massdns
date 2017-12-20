#!/bin/bash

DIR=$(dirname "$0")

wget -O- https://public-dns.info/nameservers.txt > "$DIR/../lists/public-dns.txt"
