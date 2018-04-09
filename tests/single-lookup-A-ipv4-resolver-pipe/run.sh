#!/bin/bash

DIR=$(dirname "$0")

cat "$DIR"/names.txt | "$DIR"/../../bin/massdns -c 3 --quiet -r "$DIR"/google-dns.txt | grep -E -q "`cat $DIR/expected`"
