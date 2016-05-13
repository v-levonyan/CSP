#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>

#include "client.h"

#define DATA_SIZE 100
#define BUFFER_SIZE 2000

int main(int argc, char* argv[])
{
    int sock_fd = 0;
    char data_string[DATA_SIZE] = {0};
    struct sockaddr_in serv_addr;

    if(argc < 3)
    {
	fprintf(stderr, "%s\n", "No specified address");
	exit(EXIT_FAILURE);
    }

    if( sock_create( &serv_addr, argv[1], argv[2], &sock_fd) == 1)
    {
	fprintf(stderr, "%s\n", "Connection failed");
	return 1;
    }

    //connection established

    char server_reply[BUFFER_SIZE];
    memset(server_reply, 0, BUFFER_SIZE);
    if ( read(sock_fd, server_reply, BUFFER_SIZE) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }
    printf("%s\n", server_reply);

    while(1)
    {
	fgets(data_string, (DATA_SIZE - 1), stdin);

	if(errno != 0)
	{
	    fprintf(stderr, "%s\n", strerror(errno));
	    return 1;
	}

	if( write(sock_fd, data_string, strlen(data_string)) == -1 )
	{
	    fprintf(stderr, "%s\n", strerror(errno));
	    return 1;
	}

	unsigned char hash[SHA_DIGEST_LENGTH];
	if ( read(sock_fd, hash, SHA_DIGEST_LENGTH) < 0 )
	{
	    fprintf(stderr, "%s\n", strerror(errno));
	    return 1;
	}



	for(int i = 0; i<SHA_DIGEST_LENGTH; ++i)
	{
	    printf("%02x", hash[i]);
	}

	printf("\n");
    }

    close(sock_fd);
    return 0;
}

