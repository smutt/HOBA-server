#!/bin/ksh

echo "USE hoba;"
for LINE in `cat names.txt`
do
  echo "INSERT into firstNames(firstName) values('$LINE');"
done
