#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <arpa/inet.h>
void create_socket(int *socket_desc); 
void initialize_server(struct sockaddr_in* server);
void configure();


#endif
