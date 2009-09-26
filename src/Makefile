all:
	gcc -g -O2 -Wall -I/usr/include/postgresql-8.3 -I../include -L/usr/lib/postgresql-8.3/lib -L../lib -o ../bin/oxserviced oxserviced.c -lpq

preforks:
	for ((n=1;n<256;n++)); \
	do \
		gcc -O2 -Wall -DPREFORK=$$n -I/usr/include/postgresql-8.3 -I../include -L/usr/lib/postgresql-8.3/lib -L../lib -o ../bin/oxserviced$$n oxserviced.c -lpq; \
	done
