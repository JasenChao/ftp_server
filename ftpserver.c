#include "ftpserver.h"

int socket_create(int *port)
{
    int sockfd;
    int yes = 1;
    struct sockaddr_in sock_addr;
    socklen_t addr_len = sizeof(sock_addr);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket() error");
        return -1;
    }

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(*port);
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        close(sockfd);
        perror("setsockopt() error");
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
    {
        close(sockfd);
        perror("bind() error");
        return -1;
    }

    if (*port == 0)
    {
        if (getsockname(sockfd, (struct sockaddr *)&sock_addr, &addr_len) == -1)
        {
            close(sockfd);
            perror("getsockname() error");
            return -1;
        }
        *port = ntohs(sock_addr.sin_port);
    }

    if (listen(sockfd, 10) < 0)
    {
        close(sockfd);
        perror("listen() error");
        return -1;
    }
    return sockfd;
}

int socket_accept(int sock_listen)
{
    int sockfd;
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    sockfd = accept(sock_listen, (struct sockaddr *)&client_addr, &len);

    if (sockfd < 0)
    {
        perror("accept() error");
        return -1;
    }
    return sockfd;
}

int recv_data(int sockfd, char *buf, int bufsize)
{
    size_t num_bytes;
    memset(buf, 0, bufsize);

    num_bytes = recv(sockfd, buf, bufsize, 0);
    if (num_bytes < 0)
        return -1;

    return num_bytes;
}

int send_response(ftp_server *ft, int rc)
{
    char buff[MAXSIZE];
    FILE *fp = NULL;

    switch (rc)
    {
    case 1501:
        snprintf(buff, sizeof(buff), "150 Ok to send data.\r\n");
        break;

    case 220:
        snprintf(buff, sizeof(buff), "%d Welcome.\r\n", rc);
        break;

    case 221:
        snprintf(buff, sizeof(buff), "%d Goodbye.\r\n", rc);
        break;

    case 226:
        snprintf(buff, sizeof(buff), "%d Transfer complete.\r\n", rc);
        break;

    case 331:
        snprintf(buff, sizeof(buff), "%d Please specify the password.\r\n", rc);
        break;

    case 230:
        snprintf(buff, sizeof(buff), "%d Login successful.\r\n", rc);
        break;

    case 500:
        snprintf(buff, sizeof(buff), "%d Command error.\r\n", rc);
        break;

    case 530:
        snprintf(buff, sizeof(buff), "%d Login incorrect.\r\n", rc);
        break;

    case 550:
        snprintf(buff, sizeof(buff), "%d No such file or directory.\r\n", rc);
        break;

    case 213:
        snprintf(buff, sizeof(buff), "%d %d\r\n", rc, *(int *)ft->arg);
        break;

    case 227:
        snprintf(buff, sizeof(buff), "%d Entering Passive Mode (%d,%d,%d,%d,%d,%d).\r\n", rc, (int)(inet_addr(ft->ip) & 0xff), (int)((inet_addr(ft->ip) >> 8) & 0xff), (int)((inet_addr(ft->ip) >> 16) & 0xff), (int)((inet_addr(ft->ip) >> 24) & 0xff), (int)(ft->data_port / 256), (int)(ft->data_port % 256));
        break;

    case 1502:
        fp = fopen((char *)ft->arg, "rb");
        fseek(fp, 0, SEEK_END);
        snprintf(buff, sizeof(buff), "150 Opening BINARY mode data connection for %s (%ld bytes).\r\n", (char *)ft->arg, ftell(fp));
        fclose(fp);
        break;

    default:
        return -1;
    }

    if (send(ft->sock_control, buff, strlen(buff), 0) < 0)
    {
        perror("error sending...\n");
        return -1;
    }
    return 0;
}

int retr(ftp_server *ft, char *filename)
{
    FILE *fd = NULL;
    char data[MAXSIZE];
    size_t num_read;
    fd = fopen(filename, "r");

    if (!fd)
        return send_response(ft, 550);

    else
    {
        ft->arg = filename;
        send_response(ft, 1502);
        do
        {
            num_read = fread(data, 1, MAXSIZE, fd);
            if (num_read < 0)
                printf("error in fread()\n");

            if (send(ft->sock_data, data, num_read, 0) < 0)
                printf("error sending file\n");

        } while (num_read > 0);

        fclose(fd);

        return send_response(ft, 226);
    }
}

int list(ftp_server *ft)
{
    char data[MAXSIZE];
    size_t num_read;
    FILE *fd;

    int rs = system("ls -l | tail -n+2 > tmp.txt");
    if (rs < 0)
    {
        exit(1);
    }

    fd = fopen("tmp.txt", "r");
    if (!fd)
        exit(1);

    fseek(fd, SEEK_SET, 0);

    memset(data, 0, MAXSIZE);

    while ((num_read = fread(data, 1, MAXSIZE, fd)) > 0)
    {
        if (send(ft->sock_data, data, num_read, 0) < 0)
            perror("err");

        memset(data, 0, MAXSIZE);
    }

    fclose(fd);
    system("rm tmp.txt");

    send_response(ft, 226);

    return 0;
}

static void *wait_data_sock(void *arg)
{
    ftp_server *ft = (ftp_server *)arg;
    while (1)
    {
        if ((ft->sock_data = socket_accept(ft->sock_listen)) < 0)
        {
            printf("Error accept socket");
        }
    }
}

int pasv(ftp_server *ft)
{
    if (ft->sock_data >= 0)
    {
        close(ft->sock_data);
    }
    if (ft->sock_listen >= 0)
    {
        close(ft->sock_listen);
    }
    if (ft->tid != 0 && pthread_kill(ft->tid, 0) == 0)
    {
        pthread_cancel(ft->tid);
        pthread_join(ft->tid, NULL);
    }
    int port = 0;
    if ((ft->sock_listen = socket_create(&port)) < 0)
    {
        printf("Error creating socket");
        return -1;
    }
    ft->data_port = port;

    pthread_create(&ft->tid, NULL, wait_data_sock, ft);

    return send_response(ft, 227);
}

int size(ftp_server *ft, char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        send_response(ft, 550);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fclose(fp);
    ft->arg = &file_size;
    return send_response(ft, 213);
}

int stor(ftp_server *ft, char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL)
    {
        perror("Error fopen");
        exit(1);
    }

    send_response(ft, 1501);

    char buf[MAXSIZE];
    int nread;
    while ((nread = recv_data(ft->sock_data, buf, MAXSIZE)) > 0)
    {
        fwrite(buf, 1, nread, fp);
    }

    if (nread == -1)
    {
        perror("Error recv");
        exit(1);
    }

    fclose(fp);

    return send_response(ft, 226);
}

int quit(ftp_server *ft)
{
    if (ft->sock_listen >= 0)
        close(ft->sock_listen);
    if (ft->sock_data >= 0)
        close(ft->sock_data);
    if (ft->tid != 0 && pthread_kill(ft->tid, 0) == 0)
    {
        pthread_cancel(ft->tid);
        pthread_join(ft->tid, NULL);
    }
    return 0;
}

int check_user(char *user, char *pass)
{
    char username[MAXSIZE];
    char password[MAXSIZE];
    char *pch;
    char buf[MAXSIZE];
    char *line = NULL;
    size_t len = 0;
    FILE *fd;
    int auth = 0;

    fd = fopen(".auth", "r");
    if (fd == NULL)
    {
        perror("file not found");
        exit(1);
    }
    if (getline(&line, &len, fd) != -1)
    {
        memset(username, 0, MAXSIZE);
        size_t pos = strcspn(line, "\r\n");
        line[pos] = '\0';
        strcpy(username, line);
    }

    if (getline(&line, &len, fd) != -1)
    {
        memset(password, 0, MAXSIZE);
        size_t pos = strcspn(line, "\r\n");
        line[pos] = '\0';
        strcpy(password, line);
    }

    if ((strcmp(user, username) == 0) && (strcmp(pass, password) == 0))
    {
        auth = 1;
    }
    free(line);
    fclose(fd);
    return auth;
}

int login(ftp_server *ft)
{
    char buf[MAXSIZE];
    char user[MAXSIZE];
    char pass[MAXSIZE];
    memset(user, 0, MAXSIZE);
    memset(pass, 0, MAXSIZE);
    memset(buf, 0, MAXSIZE);

    if ((recv_data(ft->sock_control, buf, sizeof(buf))) == -1)
    {
        perror("recv error\n");
        exit(1);
    }

    int i = 5;
    int n = 0;
    while (buf[i] != 0 && buf[i] != '\r' && buf[i] != '\n')
        user[n++] = buf[i++];

    send_response(ft, 331);

    memset(buf, 0, MAXSIZE);
    if ((recv_data(ft->sock_control, buf, sizeof(buf))) == -1)
    {
        perror("recv error\n");
        exit(1);
    }

    i = 5;
    n = 0;
    while (buf[i] != 0 && buf[i] != '\r' && buf[i] != '\n')
        pass[n++] = buf[i++];

    return (check_user(user, pass));
}

int recv_cmd(ftp_server *ft)
{
    char buffer[MAXSIZE];
    char cmd[5];
    char arg[MAXSIZE];

    memset(buffer, 0, MAXSIZE);
    memset(cmd, 0, 5);
    memset(arg, 0, MAXSIZE);

    if ((recv_data(ft->sock_control, buffer, sizeof(buffer))) == -1)
    {
        perror("recv error\n");
        return -1;
    }

    strncpy(cmd, buffer, 4);
    char *tmp = buffer + 5;
    strcpy(arg, tmp);

    if (strcmp(cmd, "SIZE") == 0)
    {
        return size(ft, arg);
    }
    else if (strcmp(cmd, "PASV") == 0)
    {
        return pasv(ft);
    }
    else if (strcmp(cmd, "RETR") == 0)
    {
        return retr(ft, arg);
    }
    else if (strcmp(cmd, "STOR") == 0)
    {
        return stor(ft, arg);
    }
    else if (strcmp(cmd, "LIST") == 0)
    {
        return list(ft);
    }
    else if (strcmp(cmd, "QUIT") == 0)
    {
        quit(ft);
        exit(1);
    }
    send_response(ft, 500);
    return -1;
}

void process(int sock_control)
{
    struct sockaddr_in sock_addr;
    socklen_t addr_len = sizeof(sock_addr);
    if (getsockname(sock_control, (struct sockaddr *)&sock_addr, &addr_len) == -1)
    {
        close(sock_control);
        perror("getsockname() error");
        return;
    }
    char *ip = inet_ntoa(sock_addr.sin_addr);

    ftp_server ft;
    ft.sock_control = sock_control;
    ft.sock_data = -1;
    ft.sock_listen = -1;
    memset(ft.ip, 0, 64);
    strcpy(ft.ip, ip);

    send_response(&ft, 220);

    if (login(&ft) == 1)
        send_response(&ft, 230);
    else
    {
        send_response(&ft, 530);
        exit(0);
    }

    while (1)
    {
        recv_cmd(&ft);
    }
}

int main(int argc, char *argv[])
{
    int sock_listen, sock_control, port, pid;

    if (argc != 2)
    {
        printf("usage: ./ftserve port\n");
        exit(0);
    }

    port = atoi(argv[1]);

    if ((sock_listen = socket_create(&port)) < 0)
    {
        perror("Error creating socket");
        exit(1);
    }

    while (1)
    {
        if ((sock_control = socket_accept(sock_listen)) < 0)
            break;

        if ((pid = fork()) < 0)
            perror("Error forking child process");

        else if (pid == 0)
        {
            close(sock_listen);
            process(sock_control);
            close(sock_control);
            exit(0);
        }

        close(sock_control);
    }

    close(sock_listen);

    return 0;
}
