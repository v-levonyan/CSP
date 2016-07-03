/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

#include <openssl/aes.h>

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, int* client_id);
void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, int* client_id);
size_t encrypt_AES(const unsigned char* aes_key, int key_size, const char* plain_text, unsigned char** iv_enc, unsigned char** iv_dec, AES_KEY** enc_key, AES_KEY** dec_key, unsigned char** enc_out, unsigned char** dec_out);
void decrypt_AES(unsigned char** enc_out, unsigned char** dec_out, size_t encslength, AES_KEY** dec_key, unsigned char** iv_dec );

#endif
/*----------------------------------------------------------------------------------------------*/
