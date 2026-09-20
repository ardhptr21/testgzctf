# Simple Crypto

A deliberately small crypto challenge built around one intended flaw: a reused
XOR keystream.

## Run

Build and run the service container:

```sh
docker build -t simple-crypto ./src
docker run --rm -p 8082:8082 simple-crypto
```

Inside the container, service lifecycle is managed through the provided
Makefile:

```sh
make start
make restart
make stop
```

Those targets call `supervisorctl start svc`, `supervisorctl restart svc`, and
`supervisorctl stop svc`.

## Challenge

`GET /api/flag` returns the flag encrypted with a repeating XOR keystream.
`POST /api/encrypt` encrypts attacker-chosen messages with the same keystream.
Recover the stream from chosen plaintext, then decrypt the flag ciphertext.
