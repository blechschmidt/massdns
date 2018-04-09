#!/bin/bash

DIR=$(dirname "$0")

cat "$DIR"/names.txt | "$DIR"/../../bin/massdns -c 3 --quiet -r "$DIR"/google-dns.txt | pcregrep -q -M "`cat $DIR/expected`"
