#!/bin/bash

echo "$(cat /proc/sys/kernel/random/uuid)$(cat /proc/sys/kernel/random/uuid)" | tr -d '-' >> secret.txt
echo "SECRET=$(tail -n1 secret.txt)" > .env
if command -v openssl >/dev/null; then
  if [ ! -f id_rsa ]; then
    openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:4096 -out id_rsa
  fi
  if [ ! -f id_rsa.pub ]; then
    openssl rsa -pubout -in id_rsa -out id_rsa.pub
  fi
elif command -v ssh-keygen >/dev/null; then
  if [ ! -f id_rsa ]; then
    ssh-keygen -b 4096 -m PKCS8 -t rsa -N '' -f id_rsa
  fi
  if [ ! -f id_rsa.pub ]; then
    ssh-keygen -e -m PKCS8 -f id_rsa > id_rsa.pub
  fi
else
  touch id_rsa id_rsa.pub
fi
echo "PRIVATE_KEY=\"$(cat id_rsa | sed -z 's/\n/\\n/g')\"" >> .env
