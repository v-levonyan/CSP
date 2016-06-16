#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include "hashtable.h"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct handler_args
{
    int socket;
    SSL_CTX* ctx;
};

void create_socket(int *socket_desc); 
void initialize_server(struct sockaddr_in* server);
int configure(const char* file_path);
void handler(int signal_number);
void compute_hash_file(size_t filesize, SSL* ssl);
void set_hash_table();
void* connection_handler(void*);
int send_file(int,SSL*);
int send_services(SSL*);
SSL_CTX* InitServerCTX();
int isRoot();
void ShowCerts(SSL* ssl);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);

typedef void (*fptr)(size_t, SSL*);
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
