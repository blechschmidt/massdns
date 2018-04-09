#!/bin/bash

DIR=$(dirname "$0")

FILES=$(ls "$DIR"/*/run.sh)
while read -r LINE; do
  TEST=$(basename "`dirname "$LINE"`")
  echo "===== RUN" "$TEST ====="
  "$LINE"
  RESULT=$?
  echo -n "===== RESULT: "
  if [ $RESULT -eq 0 ]; then
    echo -n "OK"
  else
    echo -n "FAILURE"
  fi
  echo " ====="
done <<< "$FILES"
