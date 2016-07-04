#ifndef SERVER_DB
#define SERVER_DB

#include "sqlite3.h"
/*---------------------------------------------------------------------------------------------------*/

int connect_to_db(sqlite3** db, const char* name);
int create_table(sqlite3** db);
int add_key_to_clients(sqlite3**, const unsigned char* key, int key_size, int* id);
int retrieve_key(void* key, int argc, char** argv, char** azColName);
void drop_table();
const unsigned char* get_key_by_id(sqlite3** db, int ID);
void string_to_hex_string(const unsigned char* str, size_t str_size, char** hex_str);

/*---------------------------------------------------------------------------------------------------*/
#endif
