#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "hashtable.h"
#include "server.h"

#define DATA_SIZE 1024

int send_services(SSL* ssl)
{
	int file_fd = open("server/services.txt", O_RDONLY);

	if ( file_fd < 0 )
	{
		fprintf(stderr, "%s", "couldn't open services.txt file");
		strerror(errno);
		return 1;
	}

	if( 1 == send_file(file_fd, ssl) )
		return 1;

	return 0;
}

int send_file(int file_fd, SSL* ssl)
{
	char buf[DATA_SIZE] = { 0 };

	while(1)
	{
		int num_read;
		char* p = buf;

		num_read = read(file_fd, buf, DATA_SIZE - 1);

		if(num_read < 0)
		{
			fprintf(stderr,"%s\n",strerror(errno));
			return 1;
		}

		if(num_read == 0)
		{
			break;
		}

		while(num_read > 0)
		{
			int num_write =  SSL_write(ssl, p, num_read);

			if(num_write < 0)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				return 1;
			}

			num_read -= num_write;
			p += num_write;
		}
	}

	return 0;
}

void compute_hash_file(size_t filesize, SSL* ssl)
{
	unsigned char hash[SHA_DIGEST_LENGTH] = { 0 };
	ssize_t bytes_read = 0;
	size_t remain_data = filesize;
	char data[DATA_SIZE] = { 0 };
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	printf("%s\n", "Receiving the file ... \n");
	while( remain_data > 0 && (bytes_read = SSL_read(ssl, data, DATA_SIZE - 1)) )
	{
		remain_data -= bytes_read;

		if(bytes_read == -1)
		{
			handle_error("data wasn't read");
		}

		SHA1_Update(&ctx, data, strlen(data));
		memset(data, 0, DATA_SIZE);
	}
	printf("%s\n","Generating final hash\n");
	if( SHA1_Final(hash, &ctx) == 0)
	{

		fprintf(stderr,"%s", "SHA final exits");
		pthread_exit(NULL);
	}
	SSL_write(ssl, hash, SHA_DIGEST_LENGTH);
	printf("%s\n", "Final hash sent to the client\n");
}


int read_request(SSL* ssl, char request[DATA_SIZE])
{
	memset(request, 0, DATA_SIZE);
	int read_size;
	read_size = SSL_read(ssl, request, DATA_SIZE);
	if(read_size < 0)
	{
		handle_error("Could not read from socket");
	}

	return read_size;
}

