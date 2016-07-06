#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/rand.h>

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

void receive_file_compute_hash_send_back(size_t filesize, SSL* ssl, int* client_id)
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
	//SSL_write(ssl, hash, SHA_DIGEST_LENGTH);
	send_buff(ssl, hash, SHA_DIGEST_LENGTH);
	printf("%s\n", "Final hash sent to the client\n");
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

void AESencryption_decryption(size_t key_size, SSL*  ssl, int* client_id)
{
    sqlite3* db;
    
    //possible memory leak
    unsigned char* key;
     
    get_key_by_id(&db, *client_id, &key);
          
    if( 4*strlen(key) != key_size) //garbage key
    {
	send_buff(ssl, "-1",2);
	fprintf(stderr,"%s\n", "Key didn't match chosen algorithm!\n");
	return;
    }
    
    else
    {	
		
	send_buff(ssl,"1",1); //OK
        
	char file_size_buf[10];
	
	memset(file_size_buf,0,10);
	
	int read_size = SSL_read(ssl, file_size_buf, 10);

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
	
//	printf("file size: %d\n", file_size);

	size_t encslength;
  
  	//be aware of memory leak 

  //  	printf("%s", "Receiving file to encrypt ... \n");
	
	ssize_t bytes_read = 0;
	size_t remain_data = file_size;
	char data[AES_BLOCK_SIZE] = { 0 };
	int fd;
	char name[] = "/tmp/encryptedXXXXXX";
	fd = mkstemp(name);
	
	while( remain_data > 0 && (bytes_read = SSL_read(ssl, data, AES_BLOCK_SIZE - 1)) )
	{
		//receiving file ...	
	
		unsigned char* iv_enc;
    		unsigned char* iv_dec;
 
    		AES_KEY* enc_key;
    		AES_KEY* dec_key;
    
		unsigned char* enc_out;
    		unsigned char* dec_out;
	
		remain_data -= bytes_read;

		if(bytes_read == -1)
		{
			handle_error("data wasn't read");
		}
		if(bytes_read == 0 )
		{
		    return;
		}
		encslength = encrypt_AES(key, key_size/8, data, &iv_enc, &iv_dec, &enc_key, &dec_key, &enc_out, &dec_out);
	
		//decrypt_AES(&enc_out, &dec_out, encslength, &dec_key, &iv_dec);
		send_buff(ssl,enc_out,strlen(enc_out));
		//printf("dec: %s\n", dec_out);
		write(fd, enc_out, strlen(enc_out));
		memset(data, 0, AES_BLOCK_SIZE);
/*	
	#####	problem here    #####	
		free(iv_enc);
		free(iv_dec);
	
		free(enc_key);
		free(dec_key);
	
		free(enc_out);
		free(dec_out);	*/
	}
	
//	send_file(fd,ssl);
	send_buff(ssl, "END", 3);
	printf("\n-----\n");
      }
}
void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, int* client_id)
{
    sqlite3* db;
    char ID_str[10] = { 0 };
    unsigned char* key = (unsigned char*)malloc(key_size+1);
    
    memset(key, 0, key_size+1);

/*############################################# BUG #######################################*/

    while(1)
    {
	if( !RAND_bytes(key, key_size) )
	{
	    fprintf(stderr, "OpenSSL reports a failure on RAND_bytes! \n");
	    /* correct here */
	    pthread_exit(NULL);
	}

	if(strlen(key) == key_size)
	{
	    break;
	}
	fprintf(stderr, "Generated key was short, now generating new one! \n");
    } 
   
    printf("generated key: ");
    print_key(key, key_size);
    
    if (add_key_to_clients(&db, key, key_size, client_id) == 1) 
    {
	fprintf(stderr, "FAILURE while adding key to DB! \n");
	pthread_exit(NULL);
    }

    // loooook here 
    sprintf(ID_str, "%d", *client_id);
/*
    printf("ID %s\n", ID_str);
*/
    if( send_buff(ssl, ID_str, 10) == 1)
    {
	fprintf(stderr, "failure on send_buff! \n");
//	 correct here 
	pthread_exit(NULL);
    } 

    unsigned char* r_key;
    get_key_by_id(&db, *client_id, &r_key);

   // printf("r_key: %s\n\n", r_key);
    char* message = "Hello David";
    size_t encslength;
  
  //be aware of memory leak 

    unsigned char* iv_enc;
    unsigned char* iv_dec;
 
    AES_KEY* enc_key;
    AES_KEY* dec_key;
    
    unsigned char* enc_out;
    unsigned char* dec_out;

    encslength = encrypt_AES(r_key, key_size, message, &iv_enc, &iv_dec, &enc_key, &dec_key, &enc_out, &dec_out);
    decrypt_AES(&enc_out, &dec_out, encslength, &dec_key, &iv_dec);
 
    printf("original:\t");
    printf("%s\n", message);

    printf("encrypt:\t");
    print_key(enc_out, encslength);
   
    printf("decrypt:\t");
    printf("%s\n",dec_out);
    
}

size_t encrypt_AES(const unsigned char* aes_key, int key_size, const char* plain_text, unsigned char** iv_enc, unsigned char** iv_dec, AES_KEY** enc_key, AES_KEY** dec_key, unsigned char** enc_out, unsigned char** dec_out) //AES-CBC-128, AES-CBC-192, AES-CBC-256
{
    // Init vector
     
    unsigned char* iv_enc_l = (unsigned char*) malloc(AES_BLOCK_SIZE);
    unsigned char* iv_dec_l = (unsigned char*) malloc(AES_BLOCK_SIZE);

    RAND_bytes(iv_enc_l, AES_BLOCK_SIZE);
    memcpy(iv_dec_l, iv_enc_l, AES_BLOCK_SIZE);
    
    // Buffers for encryption and decryption

    const size_t encslength = (( strlen(plain_text) + AES_BLOCK_SIZE)/ AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
    
    unsigned char* enc_out_l = (unsigned char*) malloc(encslength);
    unsigned char* dec_out_l = (unsigned char*) malloc(strlen(plain_text));
    
    memset(enc_out_l, 0, encslength);
    memset(dec_out_l, 0, strlen(plain_text));

    //aes-cbc-128 aes-cbc-192 aes-cbc-256

    AES_KEY* enc_key_l;
    AES_KEY* dec_key_l;
 
    enc_key_l = (AES_KEY*)malloc(sizeof(AES_KEY));    
    dec_key_l = (AES_KEY*)malloc(sizeof(AES_KEY));    
    
    memset(enc_key_l, 0, sizeof(AES_KEY));
    memset(dec_key_l, 0, sizeof(AES_KEY)); 
   
    AES_set_encrypt_key(aes_key, key_size*8, enc_key_l);

    AES_cbc_encrypt(plain_text, enc_out_l, strlen(plain_text), enc_key_l, iv_enc_l, AES_ENCRYPT);
   
    AES_set_decrypt_key(aes_key, key_size*8, dec_key_l);

    *iv_enc  = iv_enc_l;
    *iv_dec  = iv_dec_l;

    *enc_key = enc_key_l;
    *dec_key = dec_key_l;

    *enc_out = enc_out_l;
    *dec_out = dec_out_l;
     
    //return encslength;
/*  
    AES_cbc_encrypt(enc_out_l, dec_out_l, encslength, dec_key_l, iv_dec_l, AES_DECRYPT);

    printf("original:\t");
    printf("%s\n", plain_text);

    printf("encrypt:\t");
    print_key(enc_out_l, encslength);
    
    printf("decrypt:\t");
    printf("%s\n",dec_out_l);
    //print_key(dec_out, sizeof(dec_out)); */
    
   return encslength;
}

void decrypt_AES(unsigned char** enc_out, unsigned char** dec_out, size_t encslength, AES_KEY** dec_key, unsigned char** iv_dec )
{
    AES_cbc_encrypt(*enc_out, *dec_out, encslength, *dec_key, *iv_dec, AES_DECRYPT);
}

/*
void send_symmetric_key(size_t key_size, SSL* ssl)
{
    unsigned char* key = (unsigned char*)malloc(key_size);
    memset(key, 0, key_size+1);
    if( !RAND_bytes(key, key_size ) )
    {
	fprintf(stderr, "OpenSSL reports a failure on RAND_bytes! \n");
	* correct here *
	pthread_exit(NULL);
    }
    printf("key : ");
    print_key(key, key_size);

    if( send_buff(ssl, key, key_size) == 1)
    {
	fprintf(stderr, "failure on send_buff! \n");
//	 correct here 
	pthread_exit(NULL);
    } 
i}*/
