#include <stdio.h>
#include "sqlite3.h"

int AddOrUpdate = -1; // if 0 add key to db, if 1 update key

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

int create_table(sqlite3** db)
{
    char* sql;
    char* errmssg = 0;
    int rc ;
    
    sql = "CREATE TABLE IF NOT EXISTS CLIENTS(ID INT, SYMMETRIC_KEY TEXT, KEY_LENGTH INT)";

    rc = sqlite3_exec(*db, sql, 0, 0, &errmssg);
     
    if( rc != SQLITE_OK )
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return 1;
    }
	
    return 0;
}

static int retrieve_key(void* exists, int argc, char** argv, char** azColName)
{
  //  int* ex = (int*) exists;
    
    fprintf(stderr,"%s","----------------retrieved key begin-------------------\n");

    Print_key(*argv,21);

    fprintf(stderr,"%s","-----------------retrieved key end--------------------\n");
    
    return 1;
}

const unsigned char* get_key_by_id(sqlite3** db, int ID)
{
    char sql[200] = { 0 };
    char* errmssg = 0;
//    int a = 1;
//    int* exists = &a;
    sqlite3_open("SERVER_DB.dblite", db);

    sprintf(sql, "SELECT SYMMETRIC_KEY FROM CLIENTS WHERE ID=%d", ID);

    if( sqlite3_exec(*db, sql, retrieve_key, 0, &errmssg) != SQLITE_OK)
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);
	sqlite3_free(errmssg);
	return NULL;
    }

  //  if(*exists == 0)
   // {
//	return NULL;
  //  }

}

int add_key_to_clients(sqlite3** db, const unsigned char* key,int key_size, int* id)
{
    char sql[200] = { 0 };
    char* errmssg = 0;
    
    sqlite3_open("SERVER_DB.dblite", db);
    //sprintf( sql, "INSERT INTO CLIENTS VALUES (%d,%c%s%c,%d);", *id, '"', key, '"', key_size);
    
    ++AddOrUpdate;
    
    printf("AddOrUpdate: %d\n",AddOrUpdate);
    
    if(AddOrUpdate == 0)
    {
	// insert...

	sprintf( sql, "INSERT INTO CLIENTS VALUES (%d,%c%s%c,%d);", *id, '"', key, '"', key_size);
	
	sqlite3_exec(*db, sql, 0, 0, &errmssg);// != SQLITE_OK
/*	{
	    fprintf(stderr, "SQL error: %s\n", errmssg);
	    sqlite3_free(errmssg);
	    return 1;
	}  */

	printf("%s\n","Key inserted");

    }

    else
    {
	// update...
    	
	sprintf( sql, "UPDATE CLIENTS SET SYMMETRIC_KEY = %c%s%c,  KEY_LENGTH = %d WHERE ID IN (SELECT ID FROM CLIENTS WHERE ID=%d);", '"', key, '"', key_size, *id);
	
	//printf("update:\n\n%s\n\n",sql);
	
	sqlite3_exec(*db, sql, 0, 0, &errmssg);// != SQLITE_OK
/*	
	{
	    fprintf(stderr, "SQL error: %s\n", errmssg);
	    sqlite3_free(errmssg);
	    return 1;
	}
*/	
	printf("%s\n","Key updated");

    }

    return 0;
}
