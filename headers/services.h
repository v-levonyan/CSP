/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl);
void send_symmetric_key(size_t key_size, SSL* ssl);

#endif
/*----------------------------------------------------------------------------------------------*/
