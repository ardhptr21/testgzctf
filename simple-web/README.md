# Simple Web

A deliberately small web exploitation challenge with exactly one intended bug:
the preview endpoint renders user-controlled Jinja2 template text.

## Run

Build and run the service container:

```sh
docker build -t simple-web ./src
docker run --rm -p 8080:8080 simple-web
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

## Vulnerability

`POST /preview` passes the submitted `template` value directly to
`render_template_string()`. Solvers can use Jinja2 SSTI to read `/flag`.
