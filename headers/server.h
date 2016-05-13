#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <arpa/inet.h>
#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

void create_socket(int *socket_desc); 
void initialize_server(struct sockaddr_in* server);
void configure();


#endif
