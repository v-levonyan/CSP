/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, int* client_id);
void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, int* client_id);

#endif
/*----------------------------------------------------------------------------------------------*/
