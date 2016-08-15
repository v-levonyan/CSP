#ifndef SERVER_DB
#define SERVER_DB

#include "sqlite3.h"
/*---------------------------------------------------------------------------------------------------*/

int connect_to_db(sqlite3** db, const char* name);
int create_table_keys(sqlite3** db);
int create_table_users(sqlite3** db);
int add_key_to_keys(sqlite3**, const unsigned char* key, int key_size, char* user_name, char**);
//void fill_garbage_entry(sqlite3** db, int id);
static int retrieve_key(void* key, int argc, char** argv, char** azColName);
void drop_table();
const unsigned char* get_key_by_id(sqlite3** db, const char* key_id, unsigned char** key);
void string_to_hex_string(const unsigned char* str, size_t str_size, char** hex_str);
int add_RSA_key_pair_to_keys(const unsigned char* public_key, const unsigned char*private_key, const char* user_name);
int add_EC_key_pair_to_keys(const char* fk_user_name, const unsigned char* EC_public_key, const unsigned char* EC_private_key);
static int retrieve_RSA_key_ID(void* RSA_key_ID, int argc, char** argv, char** azColName);
int get_RSA_private_ID_from_keys(const char* pub_key);
int get_RSA_private_key_by_ID(int RSA_private_ID, const char* user_name, char* RSA_private_key);
static int retrieve_RSA_private_key(void* RSA_private_key, int argc, char** argv, char** azColName);
sqlite3* db;
static int check_EC_keys(void* check, int argc, char** argv, char** azColName);
/*---------------------------------------------------------------------------------------------------*/
#endif
