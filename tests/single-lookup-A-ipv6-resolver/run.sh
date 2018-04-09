#!/bin/bash

DIR=$(dirname "$0")

"$DIR"/../../bin/massdns -c 3 --quiet -r "$DIR"/google-dns.txt "$DIR"/names.txt | pcregrep -q -M "`cat $DIR/expected`"
