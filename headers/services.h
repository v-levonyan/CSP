/*----------------------------------------------------------------------------------------------*/
#ifndef SERVICES
#define SERVICES

#include <openssl/aes.h>
#include <openssl/rsa.h>

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, char* user_name);
void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, char* user_name);
void encrypt_AES(const char* plain_text, unsigned char** iv_enc, AES_KEY** enc_key, unsigned
char** enc_out);
void decrypt_AES(unsigned char* enc_out, unsigned char** dec_out, size_t encslength, AES_KEY** dec_key, unsigned char** iv_dec );
void AESencryption_decryption(size_t key_size, SSL* ssl, char* user_name);
void set_initial_vectors( unsigned char** iv_enc, unsigned char** iv_dec);
void set_enc_dec_keys(const unsigned char* aes_key, int key_size, AES_KEY** enc_key, AES_KEY**dec_key);
size_t set_enc_dec_buffers(const char* plain_text, unsigned char** enc_out, unsigned char**dec_out);
void print_key(const unsigned char* key, int size);
void RSA_key(size_t key_size, SSL* ssl, char* user_name);
RSA* RSA_generate_kay_pair();
void RSA_get_public_and_private(RSA** keypair, char** priv, char** publ);
RSA* createRSA(unsigned char* key, int public);
int RSA_public_encrypt_m(char* data, int data_len, unsigned char* key, unsigned char* encrypted);
void RSA_encrypt_m(size_t filesize, SSL*  ssl, char* user_name);

#endif
/*----------------------------------------------------------------------------------------------*/
