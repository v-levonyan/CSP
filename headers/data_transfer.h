/*-----------------------------------------------------------------------*/
#ifndef DATA_TRANSFER
#define DATA_TRANSFER
 
int send_services(SSL*);
int send_file(int, SSL*);
void receive_file_compute_hash_send_back(size_t, SSL*);
int read_request(SSL*, char*);

#endif
/*-----------------------------------------------------------------------*/
