#!/usr/bin/env bash

git clone https://gitlab.com/acefed/matchbox.git

set -e

cd matchbox
docker build -t matchbox .

if [ ! -f .env.example ]; then
  curl -sLO https://gitlab.com/acefed/matchbox/-/raw/master/.env.example
fi
if [ ! -f data/config.json.example ]; then
  mkdir -p data
  curl -sLo data/config.json.example https://gitlab.com/acefed/matchbox/-/raw/main/data/config.json.example
fi

if [ "$1" = 'https://example' ]; then
  echo 'This is an example.'
elif [ "$1" = 'https://www.example.com' ]; then
  echo 'This is an example.'
elif [ $# -gt 0 ]; then
  cat data/config.json.example | sed "s|https://example|$1|g" | sed 's|86400|null|g' > data/config.json
fi

echo "$(LC_CTYPE=C tr -dc a-zA-Z0-9 </dev/urandom | head -c48)" >> secret.txt
echo "SECRET=$(tail -1 secret.txt)" > .env
if command -v openssl >/dev/null; then
  if [ ! -f id_rsa ]; then
    openssl genpkey -quiet -algorithm rsa -pkeyopt rsa_keygen_bits:4096 -out id_rsa
  fi
  if [ ! -f id_rsa.pub ]; then
    openssl rsa -pubout -in id_rsa -out id_rsa.pub 2>/dev/null
  fi
elif command -v ssh-keygen >/dev/null; then
  if [ ! -f id_rsa ]; then
    ssh-keygen -q -b 4096 -m PKCS8 -t rsa -N '' -f id_rsa
  fi
  if [ ! -f id_rsa.pub ]; then
    ssh-keygen -e -m PKCS8 -f id_rsa > id_rsa.pub
  fi
else
  touch id_rsa id_rsa.pub
fi
echo "PRIVATE_KEY=\"$(cat id_rsa | tr '\n' '\r')\"" >> .env

docker run --init -d -v "$PWD/data:/app/data" -p "${PORT:-8080}:${PORT:-8080}" -e PORT --env-file=.env --name=matchbox matchbox
cd ..
