#include <stdio.h>
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
 
int create_table(sqlite3** db)
{
    char* sql;
    char* errmssg = 0;
    int rc ;
    
    sql = "CREATE TABLE IF NOT EXISTS CLIENTS(ID INT, SYMMETRIC_KEY TEXT)";
    rc = sqlite3_exec(*db, sql, 0, 0, &errmssg);
     
    if( rc != SQLITE_OK )
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }
	
    return 0;
}

int retrieve_key(void* key, int argc, char** argv, char** azColName)
{
 //   unsigned char* key_buf = (unsigned char*) key;
    fprintf(stderr,"%s","retrieve key\n");

    printf("key: %s\n, %s\n", *azColName, *(azColName+1));
    return 1;
}

const unsigned char* get_key_by_id(sqlite3** db, int ID)
{
    char* errmssg = 0;
    sqlite3_open("SERVER_DB.dblite", db);

    printf("%s\n","get_key_by_id");

    char* sql = "SELECT * FROM CLIENTS;";
    
    if( sqlite3_exec(*db, sql, retrieve_key, 0, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return NULL;
    }
    printf("%s\n","get_key_by_id_end");
}
int add_key_to_clients(sqlite3** db, const unsigned char* key, int* id)
{
    char* errmssg = 0;
    sqlite3_open("SERVER_DB.dblite", db);
    char* sql = "INSERT INTO CLIENTS (id, symmetric_key) VALUES (id_count, key);";
    sqlite3_exec(*db, sql, 0, 0, &errmssg);
}
