/*-----------------------------------------------------------------------*/
#ifndef DATA_TRANSFER
#define DATA_TRANSFER
 
int send_services(SSL*);
int send_file(int, SSL*);
//void receive_file_compute_hash_send_back(size_t, SSL*);
int read_request(char*);
int send_buff(SSL*, const char*, size_t);
int receive_buff(SSL* ssl, char* buff, int buff_size);
int receive_file(SSL* ssl, char* buf);
#endif
/*-----------------------------------------------------------------------*/
