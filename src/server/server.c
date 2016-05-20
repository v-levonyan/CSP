#include "server.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>
#include <openssl/sha.h>
#include <unistd.h>

#define DATA_SIZE 100

struct params_t {
    int port;
};

typedef struct params_t params_t; 

//globals

params_t* params;

void create_socket(int *socket_desc) 
{
    *socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if((*socket_desc) == -1)
    {
	handle_error("Colud not create socket");
    }
    int enable = 1;
    if (setsockopt((*socket_desc), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
}

void configure(char* file_path)
{
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);
    if(! config_read_file(&cfg, file_path))
    {
	fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
		config_error_line(&cfg), config_error_text(&cfg));
	config_destroy(&cfg);
	return;
    }
    
    params = (params_t*) malloc( sizeof(params_t) );

    setting = config_lookup(&cfg, "port");
    if(setting != NULL)
    {
	params->port = config_setting_get_int(setting);
    }
}


void initialize_server(struct sockaddr_in* server)
{
    if(params->port == 0)
    {
	params->port = 8888;
	printf("Setting listening port to default: %d\n", params->port);
    }
    else
    {
	printf("Listening port: %d\n", params->port);
    }

    memset(server, 0, sizeof(struct sockaddr_in));


    server->sin_family = AF_INET;
    server->sin_addr.s_addr = INADDR_ANY;
    server->sin_port = htons(params->port);
    free(params);
}

void compute_hash_file(size_t filesize, int* socket, unsigned char* hash)
{
    ssize_t bytes_read = 0;
    size_t remain_data = filesize;
    char data[DATA_SIZE] = { 0 };
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    printf("reading buffer...\n");
    printf("filesize: %u\n", filesize);
    while( remain_data > 0 && (bytes_read = read(*socket, data, DATA_SIZE - 1)) )
    {
	remain_data -= bytes_read;
	fprintf(stderr, "%u\n", remain_data);
	if(bytes_read == -1)
	{
	    handle_error("data wasn't read");
	}

	SHA1_Update(&ctx, data, strlen(data));
	memset(data, 0, DATA_SIZE);
    }
    printf("Computing final hash...\n");

    SHA1_Final(hash, &ctx);
}





