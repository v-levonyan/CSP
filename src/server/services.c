#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#include "sqlite3.h"
#include "openssl/ssl.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "openssl/err.h"
#include "hashtable.h"
#include "server.h"
#include "data_transfer.h"
#include "server_db.h"
#include "services.h"

#define DATA_SIZE 1024

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, char* user_name)
{
	unsigned char hash[SHA_DIGEST_LENGTH] = { 0 };
	ssize_t bytes_read = 0;
	size_t remain_data = filesize;
	char data[DATA_SIZE] = { 0 };
	
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	
	printf("%s\n", "Receiving the file ... \n");
	
	while( remain_data > 0 && (bytes_read = SSL_read(ssl, data, DATA_SIZE - 1)) )
	{
		remain_data -= bytes_read;

		if(bytes_read == -1)
		{
			handle_error("data wasn't read");
		}

		SHA1_Update(&ctx, data, strlen(data));
		memset(data, 0, DATA_SIZE);
	}
	printf("%s\n","Generating final hash\n");
	if( SHA1_Final(hash, &ctx) == 0)
	{

		fprintf(stderr,"%s", "SHA final exits");
		pthread_exit(NULL);
	}
	send_buff(ssl, hash, SHA_DIGEST_LENGTH);
	printf("%s\n", "Final hash was sent \n");
}

void print_key(const unsigned char* key, int size)
{
    int i = 0;

    for (; i < size; ++i)
    {
	printf("%01x", key[i]);
    }

    printf("%s","\n");
}

void AESencryption_decryption(size_t key_size, SSL*  ssl, char* user_name)
{
    sqlite3* db;
    
    //possible memory leak
    unsigned char* key;
     
//    get_key_by_id(&db, *client_id, &key);
          
    if( 4*strlen(key) != key_size) //garbage key
    {
	send_buff(ssl, "-1",2);
	fprintf(stderr,"%s\n", "Key didn't match chosen algorithm!\n");
	return;
    }
    
    else
    {
	// enc/dec variables 
	// possible memory leak
	
	unsigned char* iv_enc;
    	unsigned char* iv_dec;
 
    	AES_KEY* enc_key;
    	AES_KEY* dec_key;
    
	unsigned char* enc_out;
    	unsigned char* dec_out;
        
	set_initial_vectors(&iv_enc, &iv_dec);
	set_enc_dec_keys(key, key_size/8, &enc_key, &dec_key);

	send_buff(ssl,"1",1); //OK
        
	char encr_or_decr[3] = { 0 }; 

	SSL_read(ssl, encr_or_decr, 3);

	char file_size_buf[10];
	
	memset(file_size_buf,0,10);
	
	int read_size = SSL_read(ssl, file_size_buf, 10);

	if(atoi(file_size_buf) == -1) // client specified wrong file, repeat main loop
	{
	    fprintf(stderr, "Client specified wrong file, repeat main loop!\n");
	    return;
	}
        if(read_size < 0)
        {
                handle_error("Could not read from socket");
        }

        if(read_size == 0)
        {
                fprintf(stderr, "%s\n","Client disconnected, corresponding thread exited");
                pthread_exit(NULL);
        }

	size_t file_size = atoi(file_size_buf);
		
	ssize_t bytes_read = 0;
	size_t remain_data = file_size;
	char data[AES_BLOCK_SIZE + 1] = { 0 };
	int fd;
	char name[30];

	if(atoi(encr_or_decr) == 0) 
	{
	    char name[] = "/tmp/encryptedXXXXXX"; // file for temporary holding
	}

	else
	{
	    char name[] = "/tmp/decryptedXXXXXX"; 
	}

	fd = mkstemp(name);
	
	//printf("%s", "Receiving file to encrypt ... \n");

	while( remain_data > 0 && (bytes_read = SSL_read(ssl, data, AES_BLOCK_SIZE )) )
	{
		//receiving file ...	
		remain_data -= bytes_read;

		if(bytes_read == -1)
		{
			handle_error("data wasn't read");
		}
		if(bytes_read == 0 )
		{
		    return;
		}

		size_t encslength = set_enc_dec_buffers(data, &enc_out, &dec_out);
		
		if (atoi(encr_or_decr) == 0) //encrypt
		{
		    encrypt_AES(data, &iv_enc, &enc_key, &enc_out);
		    send_buff(ssl,enc_out,encslength);
		    write(fd, enc_out, encslength);
		    
		    free(enc_out);
		    free(dec_out);
		}

		else //decrypt
		{
		    decrypt_AES(data, &dec_out, bytes_read, &dec_key, &iv_dec);
		    send_buff(ssl,dec_out, bytes_read-1);
		    write(fd, dec_out, 15);
		    
		    free(enc_out);
		    free(dec_out);
		}
		
		memset(data, 0, AES_BLOCK_SIZE);
	}
	
	SSL_write(ssl, "END", 3);

	printf("\nEncryptedi/decrypted file sent.\n");

	free(iv_enc);
	free(iv_dec);
	free(enc_key);
	free(dec_key);
    }

}

void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, char* user_name)
{
    sqlite3* db;
    char* key_id;
    unsigned char* key = (unsigned char*)malloc(key_size+1);
    
    memset(key, 0, key_size+1);

    while(1)
    {
	if( !RAND_bytes(key, key_size) )
	{
	    fprintf(stderr, "OpenSSL reports a failure on RAND_bytes! \n");
	    pthread_exit(NULL);
	}

	if(strlen(key) == key_size)
	{
	    break;
	}
	fprintf(stderr, "Generated key was short, now generating new one! \n");
    } 
   
    printf("Key generated\n");
   
    if (add_key_to_clients(&db, key, key_size, user_name, &key_id) == 1) 
    {
	fprintf(stderr, "FAILURE while adding key to DB! \n");
	pthread_exit(NULL);
    }

    if( send_buff(ssl, key_id, SHA224_DIGEST_LENGTH+1) == 1)
    {
	fprintf(stderr, "failure on send_buff! \n"); 
	pthread_exit(NULL);
    } 

}

void set_initial_vectors( unsigned char** iv_enc, unsigned char** iv_dec)
{
     // Init vector
     
    unsigned char* iv_enc_l = (unsigned char*) malloc(AES_BLOCK_SIZE);
    unsigned char* iv_dec_l = (unsigned char*) malloc(AES_BLOCK_SIZE);

    memset(iv_enc_l, 0, AES_BLOCK_SIZE);
    //RAND_bytes(iv_enc_l, AES_BLOCK_SIZE);
    memcpy(iv_dec_l, iv_enc_l, AES_BLOCK_SIZE);
    
    *iv_enc = iv_enc_l;
    *iv_dec = iv_dec_l;

}

void set_enc_dec_keys(const unsigned char* aes_key, int key_size, AES_KEY** enc_key, AES_KEY** dec_key)
{
    AES_KEY* enc_key_l;
    AES_KEY* dec_key_l;
 
    enc_key_l = (AES_KEY*)malloc(sizeof(AES_KEY));    
    dec_key_l = (AES_KEY*)malloc(sizeof(AES_KEY));    
    
    memset(enc_key_l, 0, sizeof(AES_KEY));
    memset(dec_key_l, 0, sizeof(AES_KEY)); 
   
    AES_set_encrypt_key(aes_key, key_size*8, enc_key_l);
    AES_set_decrypt_key(aes_key, key_size*8, dec_key_l);

    *enc_key = enc_key_l;
    *dec_key = dec_key_l;
}

size_t set_enc_dec_buffers(const char* plain_text, unsigned char** enc_out, unsigned char** dec_out)
{
    const size_t encslength = (( strlen(plain_text) + AES_BLOCK_SIZE)/ AES_BLOCK_SIZE)*   AES_BLOCK_SIZE;
    
    unsigned char* enc_out_l = (unsigned char*) malloc(encslength + 1);
    unsigned char* dec_out_l = (unsigned char*) malloc(encslength /*strlen(plain_text)*/);
    
    memset(enc_out_l, 0, encslength);
    memset(dec_out_l, 0, encslength -1 /*strlen(plain_text)*/);
    
    *enc_out = enc_out_l;
    *dec_out = dec_out_l;

    return encslength;
}

void encrypt_AES(const char* plain_text, unsigned char** iv_enc, AES_KEY** enc_key, unsigned char** enc_out) //AES-CBC-128, AES-CBC-192, AES-CBC-256
{
        AES_cbc_encrypt(plain_text, *enc_out, strlen(plain_text), *enc_key, *iv_enc, AES_ENCRYPT);
   
}

void decrypt_AES(unsigned char* enc_out, unsigned char** dec_out, size_t encslength, AES_KEY** dec_key, unsigned char** iv_dec )
{
    AES_cbc_encrypt(enc_out, *dec_out, encslength, *dec_key, *iv_dec, AES_DECRYPT);
}

