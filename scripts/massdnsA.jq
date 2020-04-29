. |
  select(
    .class == "IN" and
    .status == "NOERROR") | 
  (.name|rtrimstr(".")) + "," + (.data.answers[] | select(.type == "A") .data)?
