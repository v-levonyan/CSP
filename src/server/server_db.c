#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>

#include "sqlite3.h"
#include "server_db.h"

int connect_to_db(sqlite3** db, const char* name)
{
    int rc;
    rc = sqlite3_open(name, db);
	
    if ( rc )
    {
	fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
	return 1;
    }
	
    return 0;
}

void Print_key(const unsigned char* key, int size)
{
    int i = 0;    
    
    for (; i < size; ++i)
    {   
	printf("%01x", key[i]);
    }     
    
    printf("%s","\n");
}

int create_table_users(sqlite3** db)
{
    char* sql; 
    char* errmssg = 0;
    int rc;

    sql = "CREATE TABLE IF NOT EXISTS users(user_name TEXT PRIMARY KEY, password TEXT);";

    rc = sqlite3_exec(*db, sql, 0, 0, &errmssg);

    if(rc != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }

    return 0;
}

int create_table_keys(sqlite3** db)
{
    char* sql;
    char* errmssg = 0;
    int rc;

    sql = "CREATE TABLE keys(fk_user_name TEXT, symmetric_key_id TEXT, symmetric_key TEXT,key_length INT,RSA_public_key TEXT, RSA_private_key TEXT, EC_public_key VARBINARY, EC_private_key TEXT, RSA_private_id INTEGER PRIMARY KEY AUTOINCREMENT,FOREIGN KEY(fk_user_name) REFERENCES users(user_name) );";

    rc = sqlite3_exec(*db, sql, 0, 0, &errmssg);

    if( rc != SQLITE_OK )
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }

    return 0;
}

static int retrieve_key(void* key, int argc, char** argv, char** azColName)
{
    char* key_buf;
    char** key_loc = (char**)key;
    int key_size = strlen(*argv);
 
    key_buf = (char*) malloc(key_size+1);
    memset(key_buf, 0, key_size+1);
    
    strcpy(key_buf,*argv);
    *key_loc = key_buf;
    
    return 1;
}

const unsigned char* get_key_by_id(sqlite3** db, const char* key_id, unsigned char** key)
{
    char sql[200] = { 0 };
    char* errmssg = 0;

    *key = (char*) calloc(1,0); //for error checking
    sprintf(sql, "SELECT SYMMETRIC_KEY FROM keys WHERE symmetric_key_id='%s'", key_id);

    if( sqlite3_exec(*db, sql, retrieve_key, key, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return NULL;
    }
}

static int retrieve_RSA_private_key(void* RSA_private_key, int argc, char** argv, char** azColName)
{
    char* RSA_private_key_loc = (char*)RSA_private_key; 
    strcpy(RSA_private_key_loc,*argv);

    return 0;
}
int get_RSA_private_key_by_ID(int RSA_private_ID, const char* user_name, char* RSA_private_key)
{
    char sql[200] = { 0 };
    char* errmssg = 0;
    
    sprintf(sql,"SELECT RSA_private_key FROM keys where fk_user_name='%s' and RSA_private_ID=%d", user_name, RSA_private_ID);

    if( sqlite3_exec(db, sql, retrieve_RSA_private_key, (void*)RSA_private_key, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	pthread_exit(NULL);
    }
   
    if(strlen(RSA_private_key) <= 2)
    {
	return 1;
    }

    return 0;
}
void string_to_hex_string(const unsigned char* str, size_t str_size, char** hex_str)
{
    char* hex = (char*)malloc(str_size*2 + 1);
    memset(hex, 0, str_size*2 + 1);

    int i;

    for( i=0; i<str_size; ++i )
    {
	sprintf( &hex[i*2], "%02X", str[i]);
    }
    
    *hex_str = hex;
}

int add_RSA_key_pair_to_keys(const unsigned char* public_key, const unsigned char* private_key, const char* user_name)
{
    char* errmssg = 0;
    char sql[7000] = { 0 };
     
    sprintf( sql, "INSERT INTO keys(fk_user_name, RSA_public_key, RSA_private_key) VALUES('%s', '%s', '%s');", user_name, public_key, private_key);

    if( sqlite3_exec(db, sql, 0, 0, &errmssg) != SQLITE_OK)	
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }

    return 0;
}

static int EC_retrieve_private_key(void* EC_private_key, int argc, char** argv, char** azColName)
{
    char* EC_private_key_loc = (char*) EC_private_key;
    
    strcpy(EC_private_key, *argv);
}

int EC_get_private_key_by_public( const char* user_name, const unsigned char* EC_public_key, unsigned char* EC_private_key)
{
     char* errmssg = 0;
     char sql [5000] = { 0 };
     
     sprintf(sql, "SELECT EC_private_key from KEYS WHERE EC_public_key='%s' and fk_user_name='%s'", EC_public_key, user_name);
    
     if( sqlite3_exec(db, sql, EC_retrieve_private_key, EC_private_key, &errmssg) != SQLITE_OK)	
     {
	 fprintf(stderr, "SQL error: %s\n", errmssg);
	 sqlite3_free(errmssg);
//	 return 1;
     }
     
     if (strlen(EC_private_key) != 56)
     {
	 return 1;    //wrong public name
     }
     
     return 0;
}

int add_EC_key_pair_to_keys(const char* user_name, const unsigned char* EC_public_key, const unsigned char* EC_private_key)
{
    char* errmssg    =   0;
    char  sql [5000] = { 0 };
        
    sprintf( sql, "INSERT INTO keys(fk_user_name, EC_public_key, EC_private_key) VALUES('%s', '%s', '%s');", user_name, EC_public_key, EC_private_key);

    if( sqlite3_exec(db, sql, 0, 0, &errmssg) != SQLITE_OK)	
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }
     
    return 0;
}

int add_key_to_keys(sqlite3** db, const unsigned char* key, int key_size, char* user_name, char** Key_ID)
{
    char* errmssg			    =	0;
    char  key_id[SHA256_DIGEST_LENGTH]	    = { 0 }; // key_id = hash(user_name + key)
    char  sql[2000]			    = { 0 };
    char* user_name_key_concatenation	    = (char*) malloc(200);

    /* possible memory leak */  
    char* hex_key;
    char* hex_user_name;
    char* hex_key_id;

    memset(user_name_key_concatenation, 0, 200);
     
    string_to_hex_string(key, key_size, &hex_key);
    string_to_hex_string(user_name, strlen(user_name), &hex_user_name);

    strcpy(user_name_key_concatenation, hex_user_name);
    strcat(user_name_key_concatenation, hex_key);
   
    SHA256(user_name_key_concatenation, strlen(user_name_key_concatenation), key_id);
    
    string_to_hex_string(key_id, SHA256_DIGEST_LENGTH, &hex_key_id);

   sprintf( sql, "INSERT INTO keys(fk_user_name, symmetric_key_id, symmetric_key, key_length,RSA_public_key, RSA_private_key) VALUES('%s', '%s', '%s', %d, '%s', '%s');", user_name, hex_key_id, hex_key, key_size, "-1", "-1");
    
    if( sqlite3_exec(*db, sql, 0, 0, &errmssg) != SQLITE_OK)	
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }
    
    *Key_ID = hex_key_id;
 
    printf("key inserted.\n");
    
    free(hex_key);
    free(hex_user_name);
    free(user_name_key_concatenation);
    return 0;
}

static int retrieve_RSA_key_ID(void* RSA_key_ID, int argc, char** argv, char** azColName)
{
    int* RSA_key_ID_loc = (int*) RSA_key_ID;
    
    *RSA_key_ID_loc = atoi(*argv);

    return 0;
}


int get_RSA_private_ID_from_keys(const char* pub_key)
{
    //////////////////////////////////////////
    int RSA_key_ID = 0;
    char sql[2000];
    char* errmssg = 0;
    sprintf(sql,"SELECT RSA_private_ID FROM keys WHERE RSA_public_key='%s'", pub_key);
    
    if( sqlite3_exec(db, sql, retrieve_RSA_key_ID, &RSA_key_ID, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return -1;
    }
    
    return RSA_key_ID;
}

