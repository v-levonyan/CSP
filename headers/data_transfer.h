/*-----------------------------------------------------------------------*/

int send_services(SSL*);
int send_file(int, SSL*);
void compute_hash_file(size_t, SSL*);
int read_request(SSL*, char*);

/*-----------------------------------------------------------------------*/
