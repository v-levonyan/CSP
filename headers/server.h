#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include "hashtable.h"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

void create_socket(int *socket_desc); 
void initialize_server(struct sockaddr_in* server);
int configure(const char* file_path);
void handler(int signal_number);
void compute_hash_file(size_t filesize, int* socket);
void set_hash_table();
void* connection_handler(void* sock_desc);
int send_file(int, int);
int send_services(int);

typedef void (*fptr)(size_t, int*);
struct hashTable* ht;
const char* conf_file;
char* program_name;

struct params_t 
{
    int port;
};

void handler(int );
typedef struct params_t params_t;
void parse_args(int argc, char *argv[]);

params_t* params;

#endif
