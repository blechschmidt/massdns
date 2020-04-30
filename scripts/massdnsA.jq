#
# $ jq -r -f massdnsA.jq < results.json
# www.xxxxxxxx.com 1.2.3.4
# www.xxxxxxxx.com 1.2.3.4
# www.yyyyyy.com 3.4.5.6
# www.zzzzzz.com 4.5.6.7
#
# Easy to modify for AAAA and other record types
#
. |
  select(
    .class == "IN" and
    .status == "NOERROR") | 
  (.name|rtrimstr(".")) + " " + (.data.answers[] | select(.type == "A") .data)?

