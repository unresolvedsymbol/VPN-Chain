#!/bin/bash

UP=
DOWN=
LAST=

while getopts “udl” OPTION; do
     case $OPTION in
         u)
             UP=1;
             ;;
         d)
             DOWN=1;
             ;;
         l)
             LAST=1;
             ;;
     esac
done

if [ -n "$UP" ]; then
  if [ -n "$LAST" ]; then
     ip route replace 0.0.0.0/1 via $6 scope link
     ip route replace 128.0.0.0/1 via $6 scope link
  else 
     ip route replace $2 via $6 scope link
  fi
fi
