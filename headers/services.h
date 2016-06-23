/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl);
int send_symmetric_key(SSL* ssl, int key_size);

#endif
/*----------------------------------------------------------------------------------------------*/
