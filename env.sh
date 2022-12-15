#!/bin/bash

echo "$(cat /proc/sys/kernel/random/uuid)$(cat /proc/sys/kernel/random/uuid)" | tr -d '-' >> secret.txt
echo "SECRET=$(tail -n1 secret.txt)" > .env
ssh-keygen -b 4096 -m PKCS8 -t rsa -N '' -f id_rsa
echo "PRIVATE_KEY=\"$(cat id_rsa | sed -z 's/\n/\\n/g')\"" >> .env
