#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>

#include "sqlite3.h"

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

int create_table_USERS_AUTHORIZATION(sqlite3** db)
{
    char* sql;
    char* errmssg = 0;
    int rc;

    sql = "CREATE TABLE IF NOT EXISTS USERS_AUTHORIZATION(USER_NAME TEXT, PASSWORD TEXT)";

    rc = sqlite3_exec(*db, sql, 0, 0, &errmssg);

    if( rc != SQLITE_OK )
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }

    return 0;
}

int create_table_CLIENTS(sqlite3** db)
{
    char* sql;
    char* errmssg = 0;
    int rc ;
    
    sql = "CREATE TABLE IF NOT EXISTS CLIENTS(USER_NAME TEXT, KEY_ID INT, SYMMETRIC_KEY TEXT, KEY_LENGTH INT)";

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
 
    key_buf = (char*) malloc(key_size);
    memset(key_buf, 0, key_size);
    
    strcpy(key_buf,*argv);
    *key_loc = key_buf;
    
    return 1;
}

const unsigned char* get_key_by_id(sqlite3** db, const char* key_id, unsigned char** key)
{
    char sql[200] = { 0 };
    char* errmssg = 0;

    sqlite3_open("SERVER_DB.dblite", db);

    *key = (char*) calloc(1,0); //for error checking
    sprintf(sql, "SELECT SYMMETRIC_KEY FROM CLIENTS WHERE KEY_ID='%s'", key_id);

    if( sqlite3_exec(*db, sql, retrieve_key, key, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return NULL;
    }
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

/*void fill_garbage_entry(sqlite3** db, int id)
{
    char sql[200] = { 0 };
    char* errmssg = 0;

    sprintf( sql, "INSERT INTO CLIENTS VALUES (%d,%c%s%c,%d);", id, '"', "-1", '"', -1);
    
    if( sqlite3_exec(*db, sql, 0, 0, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	pthread_exit(NULL);
    }
	
}
*/

int add_key_to_clients(sqlite3** db, const unsigned char* key, int key_size, char* user_name, char** Key_ID)
{
    char key_id[SHA256_DIGEST_LENGTH] = { 0 }; // key_id = hash(user_name + key)
    char* user_name_key_concatenation = (char*) malloc(200);
    char sql[200] = { 0 };
    char* errmssg = 0;
    
    memset(user_name_key_concatenation, 0, 200);
    
    /* possible memory leak */  
    char* hex_key;
    char* hex_user_name;
    char* hex_key_id;

    sqlite3_open("SERVER_DB.dblite", db);
    
    string_to_hex_string(key, key_size, &hex_key);
    string_to_hex_string(user_name, strlen(user_name), &hex_user_name);

    strcpy(user_name_key_concatenation, hex_user_name);
    strcat(user_name_key_concatenation, hex_key);
   
    SHA256(user_name_key_concatenation, strlen(user_name_key_concatenation), key_id);
    
    string_to_hex_string(key_id, SHA256_DIGEST_LENGTH, &hex_key_id);

   
    sprintf( sql, "INSERT INTO CLIENTS VALUES ('%s', '%s', '%s', %d);", user_name, hex_key_id, hex_key, key_size);

    if( sqlite3_exec(*db, sql, 0, 0, &errmssg) != SQLITE_OK)	
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }
    
    *Key_ID = hex_key_id;
 
    printf("key inserted.\n");

    return 0;
}

void drop_table()
{
    char* sql = "DROP TABLE CLIENTS";
    sqlite3* db;

    sqlite3_open("SERVER_DB.dblite", &db);
    sqlite3_exec(db, sql, 0, 0, 0);
}
