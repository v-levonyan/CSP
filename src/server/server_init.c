#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "server.h"
#include <openssl/sha.h>

#define DATA_SIZE 100

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
	exit(EXIT_FAILURE);
    }

    printf("Connection accepted");

    char data[DATA_SIZE] = { 0 };

    if(read(new_socket, data, DATA_SIZE) < 0)
    {
	fprintf(stderr, "data wasn't read");
        exit(EXIT_FAILURE);
    }

    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1( (unsigned char*)data, strlen(data) - 1, hash) );

    if ( write(new_socket, data, strlen(data)) == -1)
    {
	fprintf(stderr, strerror(errno));
	exit(EXIT_FAILURE);
    }

    close(new_socket);
    return 0;
}



