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
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

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
#define EC_PUB_KEY_BUF_LENGTH 58
#define EC_PRIVATE_KEY_BUF_LENGTH 29

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
	// possible memory leaks	
	unsigned char* iv_enc;
    	unsigned char* iv_dec;
	unsigned char* enc_out;
    	unsigned char* dec_out;
	char encr_or_decr[3] = { 0 }; 
	char file_size_buf[10];
    	char data[AES_BLOCK_SIZE + 1] = { 0 };
	int fd;
	char name[30];
	char ok[2] = { 0 };
	ssize_t bytes_read = 0;

	AES_KEY* enc_key;
    	AES_KEY* dec_key;
	
	send_buff(ssl,"1",1); //OK
        
	set_initial_vectors(&iv_enc, &iv_dec);
	set_enc_dec_keys(key, key_size/8, &enc_key, &dec_key);
        
	receive_buff(ssl, encr_or_decr, 3);
		
	memset(file_size_buf,0,10);
	
	receive_buff(ssl, ok, 2);
	
	if(atoi(ok) == -1)
	{
	    fprintf(stderr, "Client specified wrong file, repeat main loop!\n");
	    return;
	}

	receive_buff(ssl, file_size_buf, 10);

	if(atoi(file_size_buf) == -1) // client specified wrong file, repeat main loop
	{
	    fprintf(stderr, "Client specified wrong file, repeat main loop!\n");
	    return;
	}
       	size_t file_size = atoi(file_size_buf);	
	size_t remain_data = file_size;
	
	if(atoi(encr_or_decr) == 0) 
	{
	    char name[] = "/tmp/encryptedXXXXXX"; // file for temporary holding
	}

	else
	{
	    char name[] = "/tmp/decryptedXXXXXX"; 
	}

	fd = mkstemp(name);
	
	printf("%s", "Receiving file to encrypt ... \n");

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

	free(key);
	free(iv_enc);
	free(iv_dec);
	free(enc_key);
	free(dec_key);
    }
}

void add_symmetric_key_to_db_send_id(size_t key_size, SSL* ssl, char* user_name)
{
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

    free(key);
    free(key_id);
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
    char* pub_key;  //free
    char* priv_key; //free
    char RSA_private_ID_str[10] = { 0 };
    int RSA_private_ID;

    RSA* keypair = RSA_generate_kay_pair();
    RSA_get_public_and_private(&keypair, &priv_key, &pub_key);
    
    if( add_RSA_key_pair_to_keys(pub_key, priv_key, user_name) == 1)
    {
	pthread_exit(NULL);
    }

    send_buff(ssl, pub_key, strlen(pub_key)); //##########correct##########	
    SSL_write(ssl,"END", 3);
    
    RSA_private_ID = get_RSA_private_ID_from_keys(pub_key); 
    printf("RSA_private_ID = %d\n", RSA_private_ID);
    sprintf(RSA_private_ID_str,"%d", RSA_private_ID);
    
    send_buff(ssl, RSA_private_ID_str, strlen(RSA_private_ID_str));

    printf("%s\n", "Generated RSA 2048 bit public/private key pair and added to database, public one, and Private_key_ID sent to client.");
    
    RSA_free(keypair);
    free(pub_key);
    free(priv_key);
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
    
    BIO_free(pri);
    BIO_free(pub);

    *priv = pri_key;
    *publ = pub_key;
    
//    printf("\n%s\n%s\n", pri_key, pub_key);
}

RSA* createRSA( char* key, int public) 
//Create RSA variable for public/private
//Usage for public key: createRSA(“PUBLIC_KEY_BUFFER”,1);
//Usage for private key: createRSA(“PRIVATE_KEY_BUFFER”,0);
{
    RSA* rsa = NULL;
    BIO* keybio;
    keybio = BIO_new_mem_buf(key, -1);
    
    if (keybio == NULL)
    {
	printf("Failed to create key BIO");
	return NULL;
    }

    if(public)
    {
	rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	if (rsa == NULL)
	{
	    fprintf(stderr, "rsa structure is NULL\n");
	    return NULL;
	}
    }
    
    else
    {
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	
	if (rsa == NULL)
	{
	    fprintf(stderr, "rsa structure is NULL\n");
	    return NULL;
	}
    }
	
      BIO_free(keybio);
      return rsa;
}

int RSA_public_encrypt_m(char* data, int data_len, char* pub_key, unsigned char** encr)
//m for mine
{ 
    RSA* rsa = createRSA(pub_key,1);
    if(rsa == NULL)
    {	
	RSA_free(rsa);
	pthread_exit(NULL);	    
    }
    
    *encr = (unsigned char*) malloc(RSA_size(rsa));
 
    int result = RSA_public_encrypt(data_len, data, *encr, rsa, RSA_PKCS1_PADDING);
    
    RSA_free(rsa);
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

int get_public_RSA_key(SSL* ssl, char** public_key)
{
    int bytes_read; 
    char* pub_key  = (char*) malloc(2048);
    char* tmp = pub_key;
    char ok;

    SSL_read(ssl, &ok, 1);

    if(ok == '1') //CLient's specified file didn't exist
    {
	free(pub_key);
	fprintf(stderr,"%s","Wrong public key pathname from client.\n");
	return 1; 
    }

    memset(pub_key, 0, 2048);
    
    if( receive_file(ssl, pub_key) == 1) //get public key
    {
	fprintf(stderr, "%s", "Error while receiving public key.\n");
	pthread_exit(NULL);
    }
     
    *public_key = pub_key;
    return 0;
}

void RSA_encrypt_m(size_t key_size, SSL*  ssl, char* user_name)
{
    int RSA_private_ID;
    char* message;  //free
    char* pub_key;  //free
    char RSA_private_ID_str[10] = { 0 };
    unsigned char* encrypted; //free

    get_message_to_encrypt_RSA(ssl, &message);
    printf("Message: %s\n", message);

    if ( get_public_RSA_key(ssl, &pub_key) == 1)
    {
	free(message);
	return;
    }

    printf("\nRSA public key:\n%s\n",pub_key);

    int encrypted_length = RSA_public_encrypt_m(message, strlen(message), pub_key, &encrypted);
    
    if(encrypted_length == -1)
    {
	fprintf(stderr,"\nPublic Encrypt failed.\n ");
	pthread_exit(NULL);
    }
    
    send_buff(ssl, encrypted, encrypted_length);
     
    RSA_private_ID = get_RSA_private_ID_from_keys(pub_key); 
    printf("RSA_private_ID = %d\n", RSA_private_ID);
    sprintf(RSA_private_ID_str,"%d", RSA_private_ID);
    
    send_buff(ssl, RSA_private_ID_str, strlen(RSA_private_ID_str));

    printf("%s","\nRSA encryption done.\n");
    
    free(message);
    free(pub_key);
    free(encrypted);
 }

int RSA_private_decrypt_m(const char* encrypted, int encr_length, char* RSA_private_key,char* decrypted)
{
    RSA* rsa = createRSA(RSA_private_key, 0);
  
    if(rsa == NULL)
    {
	RSA_free(rsa);
	pthread_exit(NULL);	    
    }
   
    int result = RSA_private_decrypt(encr_length, encrypted, decrypted, rsa,RSA_PKCS1_PADDING);
    
    RSA_free(rsa);
    return result;
}


void RSA_decrypt_m(size_t key_size, SSL*  ssl, char* user_name)
{
    int   bytes_read;
    char  RSA_private_ID[10] = { 0 };
    char  RSA_private_key[2048] = { 0 };
    char* RSA_encrypted = malloc(4098);
    char* RSA_decrypted = malloc(4098);
    char* tmp = RSA_encrypted;
    char  ok;
     
    memset(RSA_encrypted, 0, 4098);
    memset(RSA_decrypted, 0, 4098);

    receive_buff(ssl, RSA_private_ID, 9);
    printf("RSA private ID: %s\n", RSA_private_ID);
    
    if( get_RSA_private_key_by_ID(atoi(RSA_private_ID), user_name, RSA_private_key) == 1)
    {
	//wrong ID
	free(RSA_encrypted);
	free(RSA_decrypted);
	send_buff(ssl, "-1", 2);
	return;
    }
    
    send_buff(ssl,"1", 1);
    
    SSL_read(ssl, &ok, 1);

    if(ok == '1') //CLient's specified file didn't exist
    {
	free(RSA_encrypted);
	free(RSA_decrypted);
	fprintf(stderr,"%s","Wrong public key pathname from client.\n");
	return; 
    }

    if( receive_file(ssl, RSA_encrypted) == 1) //get public key
    {
	fprintf(stderr, "%s", "Error while receiving encrypted file.\n");
	pthread_exit(NULL);
    }
   
    int decrypted_length = RSA_private_decrypt_m(RSA_encrypted, 256, RSA_private_key,RSA_decrypted);
    
    if(decrypted_length == -1)
    {
	free(RSA_encrypted);
	free(RSA_decrypted);
	fprintf(stderr,"\nPrivate decrypt failed.\n ");
	send_buff(ssl, "-1", 2);
	return;
    }
    
    send_buff(ssl, "1", 1);

    send_buff(ssl, RSA_decrypted, strlen(RSA_decrypted));
    printf("%s%s\n", "Decryption done: ",RSA_decrypted);
    
    free(RSA_encrypted);
    free(RSA_decrypted);
}

int EC_generate_keys_by_curve_name(EC_KEY** key, EC_GROUP** curve)
{ 
    if( (*curve = EC_GROUP_new_by_curve_name(NID_secp224r1)) == NULL )
    {
	fprintf(stderr, "Error while generating EC group.\n");
	return 1;
    }
   
    if( (*key = EC_KEY_new_by_curve_name(NID_secp224r1)) == NULL )
    {
	fprintf(stderr, "Error while setting up EC_KEY object.\n");
	return 1;
    }
    
    if( EC_KEY_generate_key(*key) != 1) //generates a public and private key pair
    {
	fprintf(stderr, "Error while generating EC keys.\n");
	return 1;
    }
    
    return 0;
}

int EC_keys2_oct(const EC_GROUP* curve, const EC_POINT* pub, const BIGNUM* prv, const EC_KEY* key, unsigned char**pub_buf, unsigned char** prv_buf)
{
    *pub_buf = malloc(EC_PUB_KEY_BUF_LENGTH);
    *prv_buf = malloc(EC_PRIVATE_KEY_BUF_LENGTH);
    
    memset(*pub_buf, 0, EC_PUB_KEY_BUF_LENGTH);
    memset(*prv_buf, 0, EC_PRIVATE_KEY_BUF_LENGTH);

    if( EC_POINT_point2oct(curve, pub, EC_KEY_get_conv_form(key), *pub_buf, EC_PUB_KEY_BUF_LENGTH, 0) == 0  )
    {
	fprintf(stderr, "Error while converting EC_POINT to octal string.\n");
	return 1;
    }

    if ( BN_bn2bin(prv, *prv_buf) == 0)
    {
	fprintf(stderr, "Error while converting BIG_NUM to bin string.\n");
	return 1;
    }

    return 0;
}

void hex_string_to_byte_string(const char* hex_str, unsigned char* byte_str) 
{
    int i, count, n;
    char* pos = hex_str;
/*
    for(count = 0; count < strlen(hex_str)/2+1; count++) 
    {
	sscanf(pos, "%2hhx", &byte_str[count]);
	pos += 2;
    } */

     for(i = 0; i < strlen(hex_str)/2; i++) 
     {
	 sscanf(hex_str+2*i, "%2X", &n);
	 byte_str[i] = (char)n;
     }
}
                /* bad function, need to be removed */
void byte_string_to_hex_string(const unsigned char* byte_string, char* hex_string, int size) //hex_string buffer must be large enough
{
    int i;
    
    for(i = 0; i < size/2; i++)
    {
	sprintf(hex_string+2*i, "%02X", byte_string[i]);
    }
}

void EC_key_transmission(size_t key_size, SSL*  ssl, char* user_name)
{
    unsigned char* pub_buf;
    unsigned char* prv_buf;
    char* hex_pub; 
    char* hex_prv;
  
    EC_GROUP* curve;
    EC_KEY* key;
    
    EC_POINT* pub;   
    BIGNUM* prv;

    if ( EC_generate_keys_by_curve_name(&key, &curve) == 1 )
    {	
	EC_KEY_free(key);
	pthread_exit(NULL);
    }
    
    printf("%s", "EC keys generated.\n");

    pub = EC_KEY_get0_public_key(key);
    prv = EC_KEY_get0_private_key(key);
    
    if ( EC_keys2_oct(curve, pub, prv, key, &pub_buf, &prv_buf) == 1)
    {
	send_buff(ssl, "-1", 2);
	EC_KEY_free(key);
	EC_GROUP_free(curve);
	free(pub_buf);
	free(prv_buf);
	return;
    }
    
    printf("EC public key: \n");
    print_key(pub_buf, EC_PUB_KEY_BUF_LENGTH-1);
    
    printf("EC private key: \n");
    print_key(prv_buf, EC_PRIVATE_KEY_BUF_LENGTH-1);
/*
    char* hex_pub_m = calloc(2*EC_PUB_KEY_BUF_LENGTH,1);
    
    byte_string_to_hex_string(pub_buf,  hex_pub_m, EC_PUB_KEY_BUF_LENGTH*2 - 1);
    printf("Hex_pub_m : \n%s\n", hex_pub_m);
*/
    string_to_hex_string(pub_buf, EC_PUB_KEY_BUF_LENGTH - 1,     &hex_pub);
    string_to_hex_string(prv_buf, EC_PRIVATE_KEY_BUF_LENGTH - 1, &hex_prv);
    

//    printf("hex pub: \n%s\nhex prv: \n%s\n", hex_pub, hex_prv);
	    /* remove */
/*
    char byte_pub[EC_PUB_KEY_BUF_LENGTH] = { 0 };
    char byte_prv[EC_PRIVATE_KEY_BUF_LENGTH] = { 0 };

    hex_string_to_byte_string(hex_pub, byte_pub);
    hex_string_to_byte_string(hex_prv, byte_prv);

    printf("puuuub\n");
    print_key(byte_pub, EC_PUB_KEY_BUF_LENGTH - 1);
     
    printf("prv\n");
    print_key(byte_prv, EC_PRIVATE_KEY_BUF_LENGTH - 1);
 */
/*
    printf("\nEC private key: ");
    print_key(prv_buf, EC_PRIVATE_KEY_BUF_LENGTH-1);   
      
    char* hex_pub ;//= calloc(EC_PUB_KEY_BUF_LENGTH*2, 1);
    char* hex_prv ;//= calloc(EC_PRIVATE_KEY_BUF_LENGTH*2, 1);
    byte_string_to_hex_string(pub_buf, hex_pub, EC_PUB_KEY_BUF_LENGTH-1);
    byte_string_to_hex_string(prv_buf, hex_prv, EC_PRIVATE_KEY_BUF_LENGTH-1);

    printf("hex pub: %s\n", hex_pub);
    printf("hex_prv: %s\n", hex_prv);


    string_to_hex_string(pub_buf, EC_PUB_KEY_BUF_LENGTH - 1,     &hex_pub);
    string_to_hex_string(prv_buf, EC_PRIVATE_KEY_BUF_LENGTH - 1, &hex_prv);
    
    printf("hex pub:  %s\n", hex_pub);
    printf("hex prv:  %s\n", hex_prv);

    char byte_pub[EC_PUB_KEY_BUF_LENGTH] = { 0 };
    char byte_prv[EC_PRIVATE_KEY_BUF_LENGTH] = { 0 };

    hex_string_to_byte_string(hex_pub, byte_pub);
    hex_string_to_byte_string(hex_prv, byte_prv);

    printf("puuuub\n");
    print_key(byte_pub, EC_PUB_KEY_BUF_LENGTH - 1);
    
    printf("prv\n");
    print_key(byte_prv, EC_PRIVATE_KEY_BUF_LENGTH - 1);
*/
    
    if ( add_EC_key_pair_to_keys(user_name, hex_pub, hex_prv)  == 1)
    {
	send_buff(ssl, "-1", 2);
	EC_KEY_free(key);
//	EC_POINT_free(pub);
	EC_GROUP_free(curve);
	free(hex_pub);
	free(hex_prv);
	free(pub_buf);
	free(prv_buf);
	fprintf(stderr, "Error while adding EC keys to database.\n");
	return;
    }

    printf("%s\n", "EC keys added to database.");

    send_buff(ssl, "1", 1); //Ok

    if( SSL_write(ssl, hex_pub, EC_PUB_KEY_BUF_LENGTH*2 - 1) <= 0)
    {
	EC_KEY_free(key);
	pthread_exit(NULL);
	/* handle */
    }

    EC_KEY_free(key);
   // EC_POINT_free(pub);
    EC_GROUP_free(curve);
    free(hex_pub);
    free(hex_prv);
    free(pub_buf);
    free(prv_buf);
}

void EC_get_shared_secret(size_t key_size, SSL*  ssl, char* user_name)
{
    int		    field_size, secret_len;
    
    char	    EC_public_key_buf[2*EC_PUB_KEY_BUF_LENGTH]       = { 0 };
    char	    EC_peer_public_key_buf[2*EC_PUB_KEY_BUF_LENGTH]  = { 0 };
    char	    EC_private_key_buf[2*EC_PRIVATE_KEY_BUF_LENGTH]  = { 0 };

    unsigned char*  secret;  
    unsigned char   EC_byte_pub[EC_PUB_KEY_BUF_LENGTH]		    = { 0 };
    unsigned char   EC_byte_peer_pub[EC_PUB_KEY_BUF_LENGTH]	    = { 0 };
    unsigned char   EC_byte_prv[EC_PRIVATE_KEY_BUF_LENGTH]           = { 0 };
       
    EC_KEY* key;
    EC_KEY* peer_key;
   
   
    receive_buff(ssl, EC_public_key_buf, 2*EC_PUB_KEY_BUF_LENGTH);
    printf("%s\n", EC_public_key_buf);

    if ( EC_get_private_key_by_public(user_name, EC_public_key_buf, EC_private_key_buf) == 1)
    {
	send_buff(ssl, "-1", 2);
	return;
    }
    
    send_buff(ssl, "1", 1);
    printf("EC private key got %s\n", EC_private_key_buf);
    
    hex_string_to_byte_string(EC_public_key_buf, EC_byte_pub);
    print_key(EC_byte_pub, EC_PUB_KEY_BUF_LENGTH - 1);

    hex_string_to_byte_string(EC_private_key_buf, EC_byte_prv);
    print_key(EC_byte_prv, EC_PRIVATE_KEY_BUF_LENGTH - 1);

    receive_buff(ssl, EC_peer_public_key_buf, 2*EC_PUB_KEY_BUF_LENGTH);
    
    printf("peer public key %s\n", EC_peer_public_key_buf);
 		    /* remove */
    
    hex_string_to_byte_string(EC_peer_public_key_buf, EC_byte_peer_pub);
    print_key(EC_byte_peer_pub, EC_PUB_KEY_BUF_LENGTH -1 );

    
    if( (key = EC_KEY_new_by_curve_name(NID_secp224r1)) == NULL)
    {
	fprintf(stderr,"ERROR1\n");
	/* handle */
    }
    
    if( (peer_key = EC_KEY_new_by_curve_name(NID_secp224r1)) == NULL)
    {
	fprintf(stderr,"ERROR1\n");
	/* handle */

    }
    BIGNUM*   BN_EC_byte_prv       = NULL;
    EC_POINT* EC_POINT_peer_public = NULL;

    BN_hex2bn( &BN_EC_byte_prv, EC_private_key_buf);
    fprintf(stderr, "BN print\n");
    BN_print_fp(stderr, BN_EC_byte_prv);
    fprintf(stderr, "\n");

    if( EC_KEY_set_private_key(key, BN_EC_byte_prv) != 1)
    {
	fprintf(stderr,"ERROR2\n");
	/* handle */
    }

    if( EC_POINT_hex2point(EC_KEY_get0_group(key), EC_peer_public_key_buf, EC_POINT_peer_public, 0) == NULL)
    {
	fprintf(stderr, "ERROR4\n");
    }

/*
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secret_len = (field_size+7)/8;
    
    fprintf(stderr, "secret_len %d\n", secret_len);
    if((secret = OPENSSL_malloc(secret_len)) == NULL)
    {
	fprintf(stderr, "ERROR5\n");
    }
    
    fprintf(stderr, "secret_len2 %d\n", secret_len);

    secret_len = ECDH_compute_key(secret, secret_len, EC_POINT_peer_public, key, NULL);
    
    fprintf(stderr, "secret_len3 %d\n", secret_len);

    printf("secret: %d \n%s", secret_len, secret);
    print_key(secret, secret_len);
*/
    EC_POINT* EC_POINT_shared_secret = NULL;

    printf("res: %d\n", EC_POINT_mul(EC_KEY_get0_group(key), EC_POINT_shared_secret, 0, EC_POINT_peer_public, BN_EC_byte_prv, 0));

//       if( EC_KEY_set_public_key(peer_key, EC_POINT_peer_public) != 1)
//    {
//	fprintf(stderr,"ERROR5\n");
	/* handle */
//    }

}
/*void EC_Diffie_Hellman(size_t key_size, SSL*  ssl, char* user_name)
{
    int field_size, secret_len;
    unsigned char* prv_buf;
    unsigned char* pub_buf;
    unsigned char* shared_secret_buf;
    unsigned char* secret;

    EC_GROUP* curve;
    EC_KEY* key;
    BIGNUM* prv;
    EC_POINT* pub;
    EC_POINT* Shared_secret;
    BIGNUM* pub_BN;

    if( (curve = EC_GROUP_new_by_curve_name(NID_secp224r1)) == NULL )
    {
	fprintf(stderr, "Error while generating EC group.\n");
	pthread_exit(NULL);
    }
   
    if( (key = EC_KEY_new_by_curve_name(NID_secp224r1)) == NULL )
    {
	fprintf(stderr, "Error while setting up EC_KEY object.\n");
	pthread_exit(NULL);
    }
    
    if( EC_KEY_generate_key(key) != 1) //generates a public and private key pair
    {
	fprintf(stderr, "Error while generating EC keys.\n");
	pthread_exit(NULL);
    }

    pub = EC_KEY_get0_public_key(key);
    prv = EC_KEY_get0_private_key(key);

    pub_buf = malloc(EC_PUB_KEY_BUF_LENGTH);
    memset(pub_buf, 0, EC_PUB_KEY_BUF_LENGTH);
    EC_POINT_point2oct(curve, pub, EC_KEY_get_conv_form(key), pub_buf, EC_PUB_KEY_BUF_LENGTH, 0);

    printf("%s\n", pub_buf);
    print_key(pub_buf, EC_PUB_KEY_BUF_LENGTH);
    printf("%d\n", strlen(pub_buf));
    

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));

    secret_len = (field_size + 7)/8;

    secret = OPENSSL_malloc(secret_len);
    
    secret_len = ECDH_compute_key(secret, secret_len, pub, key, NULL);

    printf("secret:   %s\n", secret);

    
   
    int sz = EC_POINT_mul(curve, Shared_secret, 0, pub, prv, 0);
    
    printf("size: %d\n", sz);
    
    shared_secret_buf = malloc(15*EC_PUB_KEY_BUF_LENGTH);
    memset(shared_secret_buf, 0, 15*EC_PUB_KEY_BUF_LENGTH);
    EC_POINT_point2oct(curve, Shared_secret, EC_KEY_get_conv_form(key), shared_secret_buf,15*EC_PUB_KEY_BUF_LENGTH, 0);

    printf("%s\n", shared_secret_buf);
    print_key(shared_secret_buf, 15*EC_PUB_KEY_BUF_LENGTH);
    
    printf("%d\n", strlen(shared_secret_buf));


    length = BN_num_bytes(pub_BN);

    pub_buf = malloc(length+1);
    memset(pub_buf, 0, length+1);

    BN_bn2bin(pub_BN, pub_buf);
    */

    
    /*length = BN_num_bytes(prv);

    prv_buf = malloc(length+1);
    memset(prv_buf, 0, length+1);
    BN_bn2bin(prv, prv_buf); */
  /* 
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if( EC_KEY_generate_key(key) != 1) //generates a public and private key pair
    {
	fprintf(stderr, "Error while generating EC keys.\n");
	pthread_exit(NULL);
    }
   */
    /* Set up private key in prv */
    /* Set up public key in pub */
/*    
    if( EC_KEY_set_public_key(key, pub) != 1)
    {	
	fprintf(stderr, "Error while generating EC public key.\n");
	pthread_exit(NULL);
    } */
   /* 
    if( EC_KEY_set_private_key(key, prv) != 1)
    {	
	fprintf(stderr, "Error while setting EC private key.\n");
	pthread_exit(NULL);
    }
   */
  //  EC_KEY_oct2key();

//}

