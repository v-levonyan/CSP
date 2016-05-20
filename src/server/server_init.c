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

#include "server.h"
#include "hashtable.h"

#define LISTEN_BACKLOG 50
#define THREAD_COUNT 5
#define HTABLE_SIZE 10

typedef void (*fptr)(size_t, int*, unsigned char* );

struct hashTable* ht;

void* connection_handler(void*);
void handler(int signal_number);

int main(int argc, char *argv[])
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = &handler;
    sigaction(SIGPIPE, &sa, NULL);

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
    for(char* p_ind = order; p_ind != spl && i != 19; ++p_ind, ++i)
    {
	command[i] = *p_ind;
    }

    return 0;
}

void* connection_handler(void* sock_desc)
{
    int socket = *( (int*)sock_desc );
    unsigned char hash[SHA_DIGEST_LENGTH];

    fptr func;

    createHashTable(HTABLE_SIZE, &ht);

    char order[100] = {0};
    char command[20] = {0};
    size_t size;

    read(socket, order, sizeof(order));
   // printf("order: %s\n", order);
    fprintf(stderr, "ord : /n %s  :ord/n", order);

    if(order_parser(order, command, &size) == 1)
    {
	return 1;
    }

    fprintf(stderr, "command %s \nsize %ld \n", command, size);
    write(socket, "I received order", 30);
    // printf("write to socket\n");
    
    addToHashTable(ht,command,compute_hash_file);
    if( valueForKeyInHashTable(ht, command, &func) == 0)
    {
	return 1;
    }

    func(size,&socket, hash);

  //  compute_hash_file(size, &socket, hash);
    write(socket, hash, SHA_DIGEST_LENGTH);
    return NULL;

}

void handler(int sig_num)
{
    return;
}
