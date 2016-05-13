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
#include <pthread.h>

#define DATA_SIZE 100
#define LISTEN_BACKLOG 50

void* connection_handler(void*);

int main(int argc, char *argv[])
{
    int socket_desc, new_socket;
    struct sockaddr_in server, client;

    create_socket(&socket_desc);
    configure();

    initialize_server(&server);

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) == -1)
    {
	handle_error("bind failed");
    }


    if (listen(socket_desc, LISTEN_BACKLOG) == -1)
    {
	handle_error("listen failed");
    }

    printf("Waiting for incoming connection...\n");

    socklen_t address_len = sizeof(struct sockaddr_in);
    
    const char* hello_message = "Hello, enter some text and I'll compute the hash for it...";

    while(1)
    {
	new_socket = accept(socket_desc, (struct sockaddr *)&client, &address_len);
	if(new_socket == -1)
	{
	    handle_error("accept failed");
	}

	printf("Connection accepted\n");

	write(new_socket, hello_message, strlen(hello_message));

	pthread_t helper_thread;
	if (pthread_create(&helper_thread, NULL, connection_handler, &new_socket) != 0)
	{
	    handle_error("Could not create thread");
	}

	pthread_join(helper_thread, NULL);
    }

    close(new_socket);
    close(socket_desc);
    return 0;
}

void* connection_handler(void* sock_desc)
{
    int socket = *( (int*)sock_desc );

    char data[DATA_SIZE];

    while(1)
    {
	if(read(socket, data, (DATA_SIZE - 1)) == -1)
	{
	    handle_error("data wasn't read");
	}

	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA1((unsigned char*)data, strlen(data), hash);

	write(socket, hash, SHA_DIGEST_LENGTH);

    }

    return NULL;
}

