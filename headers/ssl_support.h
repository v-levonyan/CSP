/*---------------------------------------------------------------------------*/
#ifndef SSL_SUPPORT
#define  SSL_SUPPORT

#include "openssl/ssl.h"

SSL_CTX* init_server_ctx();
void load_certificates(SSL_CTX*, char*, char*);
void show_certs(SSL*);

#endif

/*---------------------------------------------------------------------------*/
