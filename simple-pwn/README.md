# Simple Pwn

A deliberately small binary exploitation challenge with one intended bug: a
stack buffer overflow that can redirect execution to `win()`.

## Run

Build and run the service container:

```sh
docker build -t simple-pwn ./src
docker run --rm -p 8080:8080 simple-pwn
```

Inside the container, build and service lifecycle are managed through the
provided Makefile:

```sh
make compile
make start
make restart
make stop
```

`make compile` builds the vulnerable binary. The lifecycle targets call
`supervisorctl start svc`, `supervisorctl restart svc`, and
`supervisorctl stop svc`.

## Challenge

The TCP service prints the address of `win()`, then reads too much data into a
small stack buffer. Overflow the saved return address with the leaked `win()`
address to print `/flag`.
