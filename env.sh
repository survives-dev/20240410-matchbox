#!/bin/bash

od -vAn -tx1 -w32 -N32 /dev/urandom | tr -d ' ' >> secret.txt
echo "SECRET=$(tail -n1 secret.txt)" > .env
ssh-keygen -b 4096 -m PEM -t rsa -N '' -f id_rsa
echo "PRIVATE_KEY=\"$(cat id_rsa | sed -z 's/\n/\\n/g')\"" >> .env
