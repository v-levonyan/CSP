#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include "hashtable.h"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define exit_thread(msg) \
    do { perror(msg); pthread_exit(NULL); } while (0)

struct handler_args
{
    int socket;
    SSL_CTX* ctx;
    int client_id;
};

struct request_t 
{
    char query[30];
    int filesize;
};

void create_socket(int *socket_desc); 
void initialize_server(struct sockaddr_in* server);
int configure(const char* file_path);
void handler(int signal_number);
void set_hash_table();
int authorize_client(SSL* ssl);
int registrate_user(SSL* ssl);
void* connection_handler(void*);
void print_usage(FILE* stream, int exit_code);
void choose_corresponding_service(int, struct request_t*);

int isRoot();

typedef void (*fptr)(size_t, SSL*, int* client_id);
struct hashTable* ht;
const char* conf_file;
char* program_name;

struct params_t 
{
    int port;
};

typedef struct params_t params_t;

void handler(int );
void parse_args(int argc, char *argv[]);

params_t* params;

#endif
