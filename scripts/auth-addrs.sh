#!/bin/bash

if [ ! "$1" ]; then
	echo "Missing parameter"
	exit 1
fi

NS=$(dig +short -t NS "$1")
RESULT=""
while read -r server; do
	HAS_IPV4=$(ip -4 route | grep -q ^default; echo $?)
	HAS_IPV6=$(ip -6 route | grep -q ^default; echo $?)

	if [ "$2" != "6" ] || [ "$2" == "" ] && [ "$HAS_IPV4" == "0" ]; then
		IP4=$(dig +short -t A "$server")
		RESULT="$RESULT""$IP4"$'\n'
	fi
	if [ "$2" != "4" ] || [ "$2" == "" ] && [ "$HAS_IPV6" == "0" ]; then
                IP6=$(dig +short -t AAAA "$server")
                RESULT="$RESULT""$IP6"$'\n'
        fi
done <<< "$NS"
echo "$RESULT" | grep -v '^$'
