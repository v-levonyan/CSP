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
#include <fcntl.h>

#include "client.h"

#define DATA_SIZE 100
#define BUFFER_SIZE 2000


int sha1_of_a_file(int, unsigned char*);

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
    if (read(sock_fd, server_reply, BUFFER_SIZE) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }
    printf("%s\n", server_reply);

    while(1)
    {
	//fgets(data_string, (DATA_SIZE - 1), stdin);

	unsigned char hash[SHA_DIGEST_LENGTH] = {0};

	int err = sha1_of_a_file(sock_fd, hash);

	if(err == 1)
	{
	    fprintf(stderr, "%s\n", "err");
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
int sha1_of_a_file(int sock_fd, unsigned char* hash)
{
    int fd;
    char path[255] = { 0 };
    char buf[DATA_SIZE] = {0};
    
    puts("Enter the path of a file");
    
    fgets(path, 254, stdin);
    fprintf(stderr, "%s\n", path);

    path[strlen(path) - 1] = '\0';
    if( (fd = open(path, O_RDONLY)) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }
	 
    while(1)
    {
	int num_read;
	char* p = buf;
	    
	num_read = read(fd, buf, DATA_SIZE - 1);
	 
	if(num_read < 0)
	{
	    fprintf(stderr, "%s\n", strerror(errno));
	    return 1;
	}
		
	if(num_read == 0)
	{
	    break;
	}
		    
	while(num_read > 0)
	{
	    int num_write =  write(sock_fd, p, num_read);
	    if(num_write <= 0)
	    {
		fprintf(stderr, "%s\n", strerror(errno));
		return 1;
	    }
	    
	    num_read -= num_write;
	    p += num_write;
	}	

	memset(buf, 0, DATA_SIZE); 
    }
    
   // fprintf(stderr, "%s\n", "writing EOF");
   // fprintf(stderr, "%s\n", "-----------");
    write(sock_fd, "EOF", 4);
   // fprintf(stderr, "%s\n", "-----------");
	
    if ( read(sock_fd, hash, SHA_DIGEST_LENGTH) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }
    
    return 0;
}
