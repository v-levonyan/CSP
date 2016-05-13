#include "server.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>

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

void configure()
{
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);
    if(! config_read_file(&cfg, "server.cfg"))
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






