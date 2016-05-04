#include "thread_pool.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "server.h"
#include <string.h>
#include <stdlib.h>
#define THREAD_NUM 10
int main()
{

    int socket_desc, new_socket, *new_sock;
    struct sockaddr_in server, client;
    char* message;


    pthread_t threads[THREAD_NUM];

    create_socket(&socket_desc);

    initialize_server(&server);

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
	printf("bind failed\n");
    }

    listen(socket_desc, 3);

    printf("Waiting for incoming connection...\n");

    size_t address_len = sizeof(struct sockaddr_in);


//    create_pool(socket_desc);
    initialize_jobs();
    int i;
    for(i = 0; i < THREAD_NUM; ++i)
    {
	pthread_create(&threads[i], NULL, consumer, NULL);
    }

    while(1)
    {
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&address_len);
	if(new_socket < 0)
	{
	    perror("accept failed");
	}
	printf("Connection accepted");

	message = "Hello Client , I have received your connection. And now I will assign a handler for you\n";
	write(new_socket , message , strlen(message));

	new_sock = malloc(1);
	*new_sock = new_socket;
	pthread_create(&threads[i], NULL, producer, (void*) new_sock);
    }
    
    for(i = 0; i < THREAD_NUM; ++i)
    {
	pthread_join(threads[i], NULL);
    }

    return 0;
}
