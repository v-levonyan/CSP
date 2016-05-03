#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "client.h"

int main(int argc, char* argv[])
{
    int sock_fd = 0;
    struct sockaddr_in serv_addr;

     if(argc < 3)
     {
	 fprintf(stderr, "No specified address");
	 exit(EXIT_FAILURE);
     }

     sock_fd = sock_create( &serv_addr, argv[1], argv[2]);

     //connection established

     write(sock_fd, "Hello",5);

     return 0;
}

