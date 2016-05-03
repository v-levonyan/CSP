#include "server.h"
#include <stdio.h>
int main(int argc, char *argv[])
{
    int socket_desc, new_socket;
    struct sockaddr_in server, client;

    create_socket(&socket_desc);

    initialize_server(&server);

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
	printf("bind failed\n");
    }

    listen(socket_desc, 3);

    printf("Waiting for incoming connection...\n");

    size_t address_len = sizeof(struct sockaddr_in);

    new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&address_len);
    if(new_socket < 0)
    {
	perror("accept failed");
    }
    printf("Connection accepted");

    return 0;
}



