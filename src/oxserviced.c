#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/types.h> 
#include <sys/wait.h>

#include <uthash.h>
#include <libpq-fe.h>

#define BUFSIZE 1023
#define ERROR 42
#define SORRY 43
#define LOG   44

#define QUERY "select * from (select domain || '.oxnull.net' as \"domain\", service_id as \"service\" from webhosting.domains right join webhosting.user_services on domains.id=user_services.user_id union select attached_domain as \"domain\", service_id as \"service\" from webhosting.domains right join webhosting.user_services on domains.id=user_services.user_id) as foo where foo.domain is not null and foo.service = 0"
#define QUERY_NAME "ox_service"

#ifndef PREFORK
#define PREFORK 30
#endif

int exit_child = 0;
int cld_pids[PREFORK] = {0};

struct advertesment{
    char name[65];             /* key */
    //char service;	//what for if never read?
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct advertesment* s = NULL;
struct advertesment* users = NULL;

const char *conninfo = "host = localhost dbname = master user = main sslmode = disable";
PGconn     *conn;

void die_log(const char* msg) {
        syslog(LOG_EMERG, msg);
        closelog();
        PQfinish(conn);
        exit(1);
}

/* just connects to database*/
void connect_db() {
        conn = PQconnectdb(conninfo);
        if (PQstatus(conn) != CONNECTION_OK) {
                die_log(PQerrorMessage(conn));
        }
        PGresult *res = PQprepare(conn, QUERY_NAME, QUERY, 0, NULL);
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
                PQclear(res);
                die_log(PQerrorMessage(conn));
                /*try to reconnect*/
                PQfinish(conn);
        }
}

/*removes all items from hash and frees memory*/
void clear_hash() {
	if(!users) return;
	struct advertesment* current;
	while(users) {
		current = users;
	        HASH_DEL(users,current);
		free(current);
	}
	users = NULL;
}

/*fills hash with items from ORDBMS*/
void fill_hash() {
	int num,i;
	PGresult* res = PQexecPrepared(conn, QUERY_NAME, 0, NULL, NULL, NULL, 0);
        if(PQresultStatus(res) != PGRES_TUPLES_OK) {
	        PQclear(res);
                die_log(PQerrorMessage(conn));
        }
        num = PQntuples(res);
        for(i = 0 ; i < num; i++) {
                s = malloc(sizeof(struct advertesment));
                strcpy(s->name, PQgetvalue(res,i,0));
                //s->service = 't'; //what for if never read?
                HASH_ADD_STR(users, name, s);
		syslog(LOG_DEBUG, s->name);
        }
}


void web(int fd, const char* ip) {
	static char buffer[BUFSIZE+1]; 
	long ret;
	ret = read(fd,buffer,BUFSIZE);  
        if(ret == 0 || ret == -1){return;}
	buffer[ret]=0;
	if(buffer[ret-1]<'A'||buffer[ret-1]>'z')buffer[ret-1]=0;
	//syslog(LOG_EMERG, buffer);
	//write(fd,buffer,strlen(buffer));
	HASH_FIND_STR( users, buffer, s);
	buffer[0]='f';
	if(s!=NULL)buffer[0]='t';
	buffer[1]='\0';
	write(fd,buffer,strlen(buffer));
	//sleep(1);
}

int listenfd;

void cld_signal(int signum) {
	die_log("SIGHUP or SIGKILL received O_o");
	exit(0);
}

/* this is a child web server process, so we can exit on errors */
int child() {
        int pid, socketfd;
        static struct sockaddr_in cli_addr; /* static = initialised to zeros */
        size_t length;
        if((pid = fork()) < 0)
                die_log("fork syscall failed");
        if(pid) return pid;
        /* child */
	conn = NULL;//we don't need connection here
        signal(SIGHUP,SIG_IGN);//&cld_signal);
	signal(SIGKILL,SIG_IGN);//&cld_signal);
	length = sizeof(cli_addr);
	//sigset_t set;
        for(;;) {
		/*sigemptyset(&set);
		if(!sigpending(&set))
			die_log("sigpending failed");
		if(sigismember(&set,SIGHUP) || sigismember(&set,SIGKILL)) {
			die_log("SIGHUP or SIGKILL in a set O_o");
			exit(0); //if we got SIGKILL some time before we should just exit
		}*/
                if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
                        die_log("accept syscall failed");
                char buf[30];
                inet_ntop(AF_INET, &cli_addr.sin_addr, buf, 30);
                web(socketfd, buf);
                close(socketfd);
        }
}

void prefork_children() {
	int k;
        for(k = 0; k < PREFORK; k++) {
                cld_pids[k] = child();
        }
}


/*PID index search in cld_pids*/
int find_pid(int pid) {
	int i;
	for(i = 0; i < PREFORK; i++) {
		if(cld_pids[i] == pid)
			return i;
	}
	return -1;
}

void catch_signals(int signum) {
	//int pids[PREFORK];
	int i;
	switch(signum) {
		/*case SIGCLD:
			//respawn is normal situation while hash rereading, don't spam logs :)
			syslog(LOG_INFO,"child died");
			wait(&status);
			/if((pid = wait(&status)) > 0) {
				if((index = find_pid(pid) >= 0)) {
					cld_pids[index] = child(listenfd);
				} else
					syslog(LOG_ALERT,"PID returned by wait() is not in cld_pids");
			} else
				syslog(LOG_ALERT,"wait() didn't return a valid PID");/
			break;*/
		case SIGHUP:
			syslog(LOG_INFO, "got SIGHUP - rereading hash and recreating children");
			//backup child pids to send SIGKILL
			//memcpy(pids,cld_pids,sizeof(int)*PREFORK);
			//clear and reread hash
			clear_hash();
			fill_hash();
			//send signals
			for(i = 0; i < PREFORK; i++) {
				kill(cld_pids[i], SIGKILL);
				cld_pids[i] = child(listenfd);
				//wait(&status);
				//pause(); //wait for SIGCLD to be processed and child to be respawned
			}
			//prefork_children();
			break;
		case SIGKILL:
			close(listenfd);
			for(i = 0; i < PREFORK; i++) {
                                kill(cld_pids[i], SIGKILL);
                                //wait(&status);
                        }
			exit(0);
	}
}


int main(int argc, char **argv)
{
        int i;
        int port;
        static struct sockaddr_in serv_addr; /* static = initialised to zeros */

        if( argc != 3 ) {
                printf("oxserviced ip port\n");
                exit(0);
        }

        /* Become deamon + unstopable and no zombies children (= no wait()) */
        if(fork() != 0)
                return 0; /* parent returns OK to shell */
        signal(SIGCLD, SIG_IGN);
        signal(SIGHUP, catch_signals);
	signal(SIGKILL, catch_signals);
        for(i=0;i<32;i++)
                close(i);               /* close open files */
        setpgrp();              /* break away from process group */

        openlog("oxserviced", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO,"starting");

        /* setup the network socket */
        if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)
                die_log("socket syscall failed");
        port = atoi(argv[2]);
        if(port <= 0 || port >60000)
                die_log("Invalid port number (try 1->60000)");
        serv_addr.sin_family = AF_INET;
        inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);
        serv_addr.sin_port = htons(port);
        if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
                die_log("bind syscall failed");
        if( listen(listenfd,128) <0)
                die_log("listen syscall failed");
	//persistent connection to database
	connect_db();
	//fill hash and spawn children
	fill_hash();
	prefork_children();
        syslog(LOG_INFO,"children prefork completed, going idle");
        for(;;)
                pause(); //wait for signals and process em
}

