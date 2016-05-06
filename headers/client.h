#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

int sock_create(struct sockaddr_in* serv_addr, const char* serv_port, const char* serv_ip, int* sockfd);

