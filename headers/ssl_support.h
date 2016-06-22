/*---------------------------------------------------------------------------*/
#include "openssl/ssl.h"

SSL_CTX* InitServerCTX();
void LoadCertificates(SSL_CTX*, char*, char*);
void ShowCerts(SSL*);

/*---------------------------------------------------------------------------*/
