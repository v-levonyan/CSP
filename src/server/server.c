#include "server.h"
#include <stdlib.h>
#include <stdio.h>

void create_socket(int *socket_desc) 
{
    *socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if((*socket_desc) == -1)
    {
	printf("Colud not create socket");
	exit(0);
    }
}

void initialize_server(struct sockaddr_in* server)
{
    server->sin_family = AF_INET;
    server->sin_addr.s_addr = INADDR_ANY;
    server->sin_port = htons(8888);
}






