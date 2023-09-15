#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXSIZE 512

typedef struct _ftp_server
{
    int sock_data;
    int sock_control;
    int sock_listen;
    int data_port;
    char ip[64];
    pthread_t tid;
    void *arg;
} ftp_server;

int socket_create(int *port);

int socket_accept(int sock_listen);

int recv_data(int sockfd, char *buf, int bufsize);

int send_response(ftp_server *ft, int rc);

int retr(ftp_server *ft, char *filename);

int list(ftp_server *ft);

int pasv(ftp_server *ft);

int size(ftp_server *ft, char *filename);

int check_user(char *user, char *pass);

int login(ftp_server *ft);

int recv_cmd(ftp_server *ft);

void process(int sock_control);