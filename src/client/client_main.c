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
#include <sys/stat.h>
#include "client.h"

#define DATA_SIZE 100
#define BUFFER_SIZE 2000


int sha1_of_a_file(int, unsigned char*);
void print_sha1(const unsigned char*);

char server_reply[BUFFER_SIZE];

int main(int argc, char* argv[])
{
    int sock_fd = 0;
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

    memset(server_reply, 0, BUFFER_SIZE);

    if (read(sock_fd, server_reply, BUFFER_SIZE) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }
    printf("%s\n", server_reply);

    while(1)
    {
	unsigned char hash[SHA_DIGEST_LENGTH] = {0};

	if( sha1_of_a_file(sock_fd, hash) == 1)
	{
	    return 1;
	}

	print_sha1(hash);
    }

    close(sock_fd);
    return 0;
}

int sha1_of_a_file(int sock_fd, unsigned char* hash)
{
    int fd;
    size_t file_size;
    char path[255] = { 0 };
    char buf[DATA_SIZE] = {0};
    struct stat st;
    char f_size_str[40];

    puts("Enter the path of a file");

    fgets(path, 254, stdin);
 //   fprintf(stderr, "%s\n", path);

    path[strlen(path) - 1] = '\0';

    if( (fd = open(path, O_RDONLY)) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }

    if(stat(path, &st) == -1)
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }

    file_size = st.st_size;
    memset(f_size_str, 0, 40);

    sprintf(f_size_str, "%s %ld","compute_file_hash", file_size);
    fprintf(stderr, "%s\n", f_size_str);

    memset(server_reply, 0, BUFFER_SIZE);
    write(sock_fd, f_size_str, strlen(f_size_str));
    read(sock_fd, server_reply, BUFFER_SIZE-1);

    fprintf(stderr, "%s\n", server_reply);

    while(1)
    {
	int num_read;
	char* p = buf;

	num_read = read(fd, buf, DATA_SIZE - 1);
//	fprintf(stderr, "%s", buf);

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


    if ( read(sock_fd, hash, SHA_DIGEST_LENGTH) < 0 )
    {
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
    }

    close(fd);
    return 0;
}

void print_sha1(const unsigned char* hash)
{
    for(int i = 0; i<SHA_DIGEST_LENGTH; ++i)
    {
	printf("%02x", hash[i]);
    }

    printf("\n");
}
