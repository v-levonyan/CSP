#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define FAIL 1 
#define SUCCESS 0

int sock_create(struct sockaddr_in* serv_addr, const char* serv_port, const char* serv_ip, int* sock)
{
    int port = 0;

    if( (*sock = socket(AF_INET, SOCK_STREAM, 0) ) < 0)
    {
	return FAIL;
    }

    memset(serv_addr, 0, sizeof(*serv_addr));
    port = atoi(serv_port); 
    
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(port);
    serv_addr->sin_addr.s_addr = inet_addr(serv_ip);

    if( connect(*sock, (struct sockaddr*) serv_addr, sizeof(*serv_addr)) < 0)
    {
	return FAIL;
    }

    return SUCCESS;
}

