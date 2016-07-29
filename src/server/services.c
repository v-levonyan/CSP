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
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

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
    unsigned char* key = 0;
    char key_id[SHA256_DIGEST_LENGTH * 2+1] = { 0 };

    receive_buff(ssl,key_id, SHA256_DIGEST_LENGTH*2+1);
    
    get_key_by_id(&db, key_id, &key);
    
    if( 4*strlen(key) != key_size) //garbage key
    {
	send_buff(ssl, "-1",2);
	fprintf(stderr,"%s\n", "Key didn't match to the chosen algorithm!\n");
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

	printf("sizes %d : %d\n", strlen(key), key_size);
	if(strlen(key) == key_size)
	{
	    break;
	}
	fprintf(stderr, "Generated key was short, now generating new one! \n");
    } 
   
    printf("Key generated\n");
   
    if (add_key_to_keys(&db, key, key_size, user_name, &key_id) == 1) 
    {
	fprintf(stderr, "FAILURE while adding key to DB! \n");
	pthread_exit(NULL);
    }

    printf("key_id: %s\n", key_id);
    if( send_buff(ssl, key_id, strlen(key_id)) == 1)
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

RSA* RSA_generate_kay_pair()
{
    return RSA_generate_key(2048,3,NULL,NULL);
}

void RSA_key(size_t key_size, SSL*  ssl, char* user_name)
{
    char* pub_key;
    char* priv_key;

    RSA* keypair = RSA_generate_kay_pair();
    
    RSA_get_public_and_private(&keypair, &priv_key, &pub_key);
    
    //printf("puuub: %s\n", pub_key);
    SSL_write(ssl, pub_key, strlen(pub_key));	
    SSL_write(ssl,"END", 3);
    printf("%s\n", "Generated RSA 2048 bit public/private key pair, public one sent to client.");
}

void RSA_get_public_and_private(RSA** keypair, char** priv, char** publ)
{
    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, *keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, *keypair);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char* pri_key = malloc(pri_len + 1);
    char* pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    
    *priv = pri_key;
    *publ = pub_key;
    
//    printf("\n%s\n%s\n", pri_key, pub_key);
}

RSA* createRSA(unsigned char* key, int public) 
//Create RSA variable for public/private
//Usage for public key: createRSA(“PUBLIC_KEY_BUFFER”,1);
//Usage for private key: createRSA(“PRIVATE_KEY_BUFFER”,0);
{
    RSA* rsa = NULL;
    BIO* keybio;
    keybio = BIO_new_mem_buf(key, -1);
    
    if (keybio==NULL)
    {
	printf( "Failed to create key BIO");
	return 0;
    }

    if(public)
    {
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    
    else
    {
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
							 
    return rsa;
}

int RSA_public_encrypt_m(char* data, int data_len, unsigned char* key, unsigned char* encrypted)
//m for mine
{
    RSA* rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
    return result;
}


void get_message_to_encrypt_RSA(SSL* ssl, char** message)
{
    char* mssg;
    mssg = (char*) malloc(200);
    
    memset(mssg, 0, 200);
    receive_buff(ssl, mssg, 200);
    
    *message = mssg;
}

void get_public_RSA_key(SSL* ssl, unsigned char** public_key)
{
    int bytes_read; 
    unsigned char* pub_key  = (unsigned char*) malloc(2048);
    char* tmp = pub_key;
    
    memset(pub_key, 0, 2048);

    while(1)
    {
	bytes_read = SSL_read(ssl, tmp, 100);
    
	if(bytes_read == -1)
	{
	    handle_error("data wasn't read");
	}

	if(strcmp(tmp,"##END##") == 0)
	{
	    memset(tmp, 0, 7);
	    break;
	}
	tmp += bytes_read;
    }
    
    *public_key = pub_key;
}
void RSA_encrypt_m(size_t key_size, SSL*  ssl, char* user_name)
{
    char* message;
    unsigned char* pub_key;

    get_message_to_encrypt_RSA(ssl, &message);
    printf("Message: %s\n", message);

    get_public_RSA_key(ssl, &pub_key);
    printf("\nRSA public key:\n%s\n",pub_key);
}
