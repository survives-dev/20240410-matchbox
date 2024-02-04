# Matchbox

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://gitlab.com/acefed/matchbox)

[https://acefed.gitlab.io/matchbox](https://acefed.gitlab.io/matchbox)

```shell
$ command -v bash cat curl docker git openssl sed
$ command -v bash cat curl docker git openssl sed | wc -l
7
```

```shell
$ curl -fsSL https://gitlab.com/acefed/matchbox/-/raw/main/install.sh | PORT=8080 bash -s -- https://www.example.com
$ curl https://www.example.com/
Matchbox: ActivityPub@Hono
```

```shell
$ curl -fsSL https://gitlab.com/acefed/matchbox/-/raw/main/setup.sh | bash -s -- https://www.example.com
$ docker run --init -d -v "$PWD/data:/app/data" -p 8080:8080 -e PORT=8080 --env-file=.env --name=matchbox registry.gitlab.com/acefed/matchbox/main
$ curl https://www.example.com/
Matchbox: ActivityPub@Hono
```

SPDX-License-Identifier: MIT
