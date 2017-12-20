#!/bin/bash

if [ ! "$1" ]; then
	echo "Missing parameter"
	exit 1
fi

NS=$(dig +short -t NS "$1")
RESULT=""
while read -r server; do
	if [[ "$2" -ne "6" ]]; then
		IP4=$(dig +short -t A "$server")
		RESULT="$RESULT""$IP4"$'\n'
	fi
	if [[ "$2" -ne "4" ]]; then
                IP6=$(dig +short -t AAAA "$server")
                RESULT="$RESULT""$IP6"$'\n'
        fi
done <<< "$NS"
echo "$RESULT" | grep -v '^$'
