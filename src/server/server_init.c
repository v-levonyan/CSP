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
#include <signal.h>
#include <getopt.h>

#define LISTEN_BACKLOG 50
#define THREAD_COUNT 5

void* connection_handler(void*);
void handler(int signal_number);
void print_usage(FILE* stream, int exit_code);
const char* program_name;

int main(int argc, char *argv[])
{
    int next_option;
    const char* const short_options = "hc:";
    const struct option long_options[] = {
	{ "help", 0, NULL, 'h' },
	{ "conf", 1, NULL, 'c' },
	{ NULL,   0, NULL,  0  }
    };

    const char* conf_file = NULL;
    program_name = argv[0];

    do
    {
	next_option = getopt_long(argc, argv, short_options, long_options, NULL);

	if(optarg == NULL)
	{
	    print_usage(stderr, 1);
	}
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
// Let's do the main job...
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = &handler;
    sigaction(SIGPIPE, &sa, NULL);

    int socket_desc, new_socket;
    struct sockaddr_in server, client;

    create_socket(&socket_desc);
    configure(conf_file);

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

    pthread_t helper_thread[THREAD_COUNT];

    for(int i = 0; i < THREAD_COUNT; ++i)
    {
	new_socket = accept(socket_desc, (struct sockaddr *)&client, &address_len);
	if(new_socket == -1)
	{
	    handle_error("accept failed");
	}

	printf("Connection accepted\n");

	write(new_socket, hello_message, strlen(hello_message));

	if (pthread_create(&helper_thread[i], NULL, connection_handler, &new_socket) != 0)
	{
	    handle_error("Could not create thread");
	}

    }

    for(int i = 0; i < THREAD_COUNT; ++i)
    {
	pthread_join(helper_thread[i], NULL);
    }
    close(new_socket);
    close(socket_desc);
    return 0;
}

void* connection_handler(void* sock_desc)
{
    int socket = *( (int*)sock_desc );
    
    unsigned char hash[SHA_DIGEST_LENGTH];

    char order[100] = {0};
    
    read(socket, order, sizeof(order));
    printf("order: %s\n", order);

    char* token = strtok(order, " ");
    char function[30] = {0};
    strcpy(function, token) ;
    token = strtok(NULL, " ");

    char size_str[20] = {0};
    strcpy(size_str, token) ;

    printf("function: %s\n", function);
    size_t size = atoi(size_str);
    printf("size: %u\n", size);
    if (strcmp(function, "compute_file_hash") == 0)
    {
	printf("received order to compute hash of a file...\n");
	compute_hash_file(size, &socket, hash);
    }

    printf("write to socket\n");
    write(socket, hash, SHA_DIGEST_LENGTH);
    return NULL;

}

void handler(int sig_num)
{
    return;
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
