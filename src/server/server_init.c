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
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "server.h"

#define listen_backlog 50
#define thread_count 5

int main(int argc, char *argv[])
{
    parse_args(argc, argv);
    set_hash_table();

    // let's do the main job

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = &handler;
    sigaction(SIGPIPE, &sa, NULL);

    int socket_desc;
    struct sockaddr_in server, client;
    
    create_socket(&socket_desc);
    
    if( !configure(conf_file) )
    {
	handle_error("invalid conf file");
    }

    initialize_server(&server);

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) == -1)
    {
	handle_error("bind failed");
    }

    if (listen(socket_desc, listen_backlog) == -1)
    {
	handle_error("listen failed");
    }

    printf("waiting for incoming connection...\n");

    socklen_t address_len = sizeof(struct sockaddr_in);

    pthread_t helper_thread[thread_count];

    for(int i = 0; i < thread_count; ++i)
    {
	struct handler_args args;

	SSL_library_init();
	args.ctx = InitServerCTX();
	LoadCertificates(args.ctx,"mycert.pem","mycert.pem");

	SSL* ssl;

	args.socket = accept(socket_desc, (struct sockaddr *)&client, &address_len);

	if(args.socket == -1)
	{
	    handle_error("accept failed");
	}

	printf("connection accepted: %s:%d\n",inet_ntoa(client.sin_addr),
	ntohs(client.sin_port));

	if (pthread_create(&helper_thread[i], NULL, connection_handler, (void*)&args) != 0)
	{
	    handle_error("could not create thread");
	}
    }

    for(int i = 0; i < thread_count; ++i)
    {
	pthread_join(helper_thread[i], NULL);
    }

    close(socket_desc);

    return 0;
}
