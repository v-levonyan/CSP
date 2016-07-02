/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

#include <openssl/aes.h>

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, int* client_id);
void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, int* client_id);
size_t  encrypt_AES(const unsigned char* aes_key, int key_size, AES_KEY* enc_key, AES_KEY* dec_key, const char* plain_text,     char* encrypt, unsigned char* iv_enc, unsigned char* iv_dec);
void decrypt_AES(const unsigned char* encrypted, size_t encslength, unsigned char* decrypt, AES_KEY* dec_key, unsigned char* iv_dec);

#endif
/*----------------------------------------------------------------------------------------------*/
