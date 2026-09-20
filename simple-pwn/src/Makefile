.PHONY: compile start restart stop

compile:
	gcc -O0 -fno-stack-protector -no-pie -z noexecstack -Wall -Wextra -o chall chall.c

start:
	supervisorctl start svc

restart:
	supervisorctl restart svc

stop:
	supervisorctl stop svc
