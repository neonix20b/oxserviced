DIRS = src

all:
	for dir in ${DIRS} ; do ( cd $$dir ; make all ) ; done

install:
	cp bin/oxserviced /home/oxpanel/bin

preforks:
	for dir in ${DIRS} ; do ( cd $$dir ; make preforks ) ; done

