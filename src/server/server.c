#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include "hashtable.h"
#include "server.h"

#define DATA_SIZE 1024
#define HTABLE_SIZE 10

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

int configure(const char* file_path)
{
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);
    if(! config_read_file(&cfg, file_path))
    {
	fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
		config_error_line(&cfg), config_error_text(&cfg));
	config_destroy(&cfg);
	return 0;
    }
    
    params = (params_t*) malloc( sizeof(params_t) );

    setting = config_lookup(&cfg, "port");
    if(setting != NULL)
    {
	params->port = config_setting_get_int(setting);
    }
    return 1;
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
 
    while( remain_data > 0 && (bytes_read = read(*socket, data, DATA_SIZE - 1)) )
    {
	remain_data -= bytes_read;

	if(bytes_read == -1)
	{
	    handle_error("data wasn't read");
	}

	SHA1_Update(&ctx, data, strlen(data));
	memset(data, 0, DATA_SIZE);
    }


    if( SHA1_Final(hash, &ctx) == 0)
    {
	fprintf(stderr,"%s", "SHA final exits");
	pthread_exit(NULL);
    }
}
int order_parser(const char* order, char* command, size_t* size)
{
    char* spl = strchr(order, ' ');
    char size_buf [20] = {0};
    
    if(spl == NULL)
    {
	return 1;
    }

    strncpy(size_buf, spl+1, 19);

    *size = atoi(size_buf);
    int i = 0;
    const char* p_ind;
    for(p_ind = order; p_ind != spl && i != 49; ++p_ind, ++i)
    {
	command[i] = *p_ind;
    }

    return 0;
}

void set_hash_table()
{
    createHashTable(HTABLE_SIZE, &ht);
    addToHashTable(ht,"compute_file_hash",compute_hash_file);
}

void* connection_handler(void* sock_desc)
{
    int socket = *( (int*)sock_desc );
    unsigned char hash[SHA_DIGEST_LENGTH];

    fptr func;

    char order[100] = {0};
    char command[50] = {0};
    size_t size;

    read(socket, order, sizeof(order));

    if(order_parser(order, command, &size) == 1)
    {
	return NULL;
    }

    write(socket, "I received order", 30);
    
    if( valueForKeyInHashTable(ht, command, &func) == 0)
    {
	return NULL;
    }

    func(size,&socket, hash);

    write(socket, hash, SHA_DIGEST_LENGTH);
    return NULL;

}

void print_usage(FILE* stream, int exit_code)
{
    fprintf (stream, "Usage: %s options [ inputfile .... ]\n", program_name);
    fprintf (stream,
	    " -h --help	    Display this usage information.\n"
	    " -c --conf	    filepath read parameters from file.\n"
	    );
    exit (exit_code);
}

void handler(int signum)
{
    printf("%s\n","Recevied SIGPIPE signal from a client, the thread exits");
    pthread_exit(NULL);
    return;
}
void parse_args(int argc, char *argv[])
{
    int next_option;
    const char* const short_options = "hc:";
    const struct option long_options[] = {
	{ "help", 0, NULL, 'h' },
	{ "conf", 1, NULL, 'c' },
	{ NULL,   0, NULL,  0  }
    };

    program_name = argv[0];

    do
    {
	next_option = getopt_long(argc, argv, short_options, long_options, NULL);

	switch(next_option)
	{
	    case 'h':
		print_usage(stdout, 0);
		
	    case 'c':
		conf_file = optarg;
		break;
	    case '?':
		print_usage(stderr, 1);
	    case -1:
		break;
	    default:
		abort();
	}
    }
    while(next_option != -1);

    if(optind == 1)
    {
	fprintf(stderr, "No options specified\n");
	print_usage(stderr, 1);
    }

    if(access(conf_file, F_OK) == -1)
    {
	fprintf(stderr, "No such file\n");
	print_usage(stderr, 1);
    }
}
