#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "hashtable.h"
#include "server.h"
#include "ssl_support.h"
#include "data_transfer.h"
#include "services.h"
#include "server_db.h"

#define FAIL -1
#define DATA_SIZE 1024
#define HTABLE_SIZE 10

void create_socket(int *socket_desc)
{
	*socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if((*socket_desc) == -1)
		handle_error("Could not create socket");

	int enable = 1;
	if (setsockopt((*socket_desc), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
}

void parse_args(int argc, char *argv[])
{
	int next_option;
	const char* const short_options = "hc:";
	const struct option long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "conf", 1, NULL, 'c' },
		{ NULL,   0, NULL,  0  }
	};

	program_name = argv[0];

	do
	{
		next_option = getopt_long(argc, argv, short_options, long_options, NULL);

		switch(next_option)
		{
			case 'h':
				print_usage(stdout, 0);

			case 'c':
				conf_file = optarg;
				break;
			case '?':
				print_usage(stderr, 1);
			case -1:
				break;
			default:
				abort();
		}
	}
	while(next_option != -1);

	if(optind == 1)
	{
		fprintf(stderr, "No options specified\n");
		print_usage(stderr, 1);
	}

	if(access(conf_file, F_OK) == -1)
	{
		fprintf(stderr, "No such file\n");
		print_usage(stderr, 1);
	}
}

int configure(const char* file_path)
{
	config_t cfg;
	config_setting_t *setting;

	config_init(&cfg);
	if(! config_read_file(&cfg, file_path))
	{
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
				config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return 0;
	}

	params = (params_t*) malloc( sizeof(params_t) );

	setting = config_lookup(&cfg, "port");
	if(setting != NULL)
	{
		params->port = config_setting_get_int(setting);
	}
	return 1;
}

void initialize_server(struct sockaddr_in* server)
{
	if(params->port == 0)
	{
		params->port = 8888;
		printf("Setting listening port to default: %d\n", params->port);
	}
	else
	{
		printf("Listening port: %d\n", params->port);
	}

	memset(server, 0, sizeof(struct sockaddr_in));


	server->sin_family = AF_INET;
	server->sin_addr.s_addr = INADDR_ANY;
	server->sin_port = htons(params->port);
	free(params);
}

void order_parser(char* order, struct request_t* request)
{
	char* token;
	token = strtok(order, ":");
	strncpy(request->query, token, sizeof(request->query));
	token = strtok(NULL, ":");
	request->size = atoi(token);
}

void set_hash_table()
{
	ht = NULL;
	createHashTable(HTABLE_SIZE, &ht);
	if(ht == NULL)
	{
	    fprintf(stderr, "Error while creating hashtable.\n");
	    pthread_exit(NULL);
	}
	addToHashTable(ht, "symmetric_key",     add_symmetric_key_to_db_send_id);
	addToHashTable(ht, "compute_file_hash", receive_file_compute_hash_send_back);
	addToHashTable(ht, "AESencr_decr",      AESencryption_decryption);
	addToHashTable(ht, "RSA_key",           RSA_key);
	addToHashTable(ht, "encryptik",         RSA_encrypt_m); //##### change the name #####
	addToHashTable(ht, "decryptik",         RSA_decrypt_m);
}

void choose_corresponding_service(int serv, struct request_t* request)
{	
	switch(serv)
	{
	    case 1:
		strcpy(request->query, "compute_file_hash");
		break;
	    case 2:
		strcpy(request->query, "compute_string_hash");
		break;
	    case 3:
		strcpy(request->query, "symmetric_key");
		break;
	    case 4:
		strcpy(request->query, "symmetric_key");
		break;
	    case 5:
		strcpy(request->query, "symmetric_key");
		break;
	    case 6:
		strcpy(request->query, "symmetric_key");
		break; 
	    case 7:
		strcpy(request->query, "symmetric_key");
		break;
	    case 8:
		strcpy(request->query, "----");
		break;
	    case 9:
		strcpy(request->query, "symmetric_key");
		break;
	    case 10:
		strcpy(request->query, "AESencr_decr");
		break;
	    case 11:
		strcpy(request->query, "AESencr_decr");
		break;
	    case 12:
		strcpy(request->query, "AESencr_decr");
		break;
	    case 18:
		strcpy(request->query, "RSA_key");
		break;
	    case 19:
		strcpy(request->query, "encryptik"); //##### change the name #####
		break;
	    case 20:
		strcpy(request->query, "decryptik");
		break;
	}

}

int look_up_aux(void* free_or_busy, int argc, char** argv, char** azColName)
{
    int* f_or_b = (int*) free_or_busy;
    
    if(*argv != 0) //username is busy
    {
	*f_or_b = 1;
	return 1;
    }

    return 0;
}

int lookup_for_username(char* user_name)
{  
    int free_or_busy = 0; // free
    char sql[200] = { 0 };
    char* errmssg = 0;
  
    sprintf(sql, "SELECT user_name FROM users WHERE USER_NAME = %c%s%c", '"', user_name,  '"');
      
    if( sqlite3_exec(db, sql, look_up_aux, &free_or_busy, &errmssg) != SQLITE_OK)
    {	
	fprintf(stderr, "SQL error: %s\n", errmssg);
    }

    printf("%s", free_or_busy  == 0 ? "Username was free.\n" : "Username was busy.\n");
    
    if( free_or_busy == 1 )
    {
	return 1;
    }
    return 0;
}

void insert_username_password_to_db(const char* user_name, const char* password)
{
    unsigned char sha256_of_password[SHA256_DIGEST_LENGTH] = { 0 };
    char* hex_hash;
    char sql[200] = { 0 };
    char* errmssg = 0;
   
    SHA256(password, strlen(password), sha256_of_password);
    string_to_hex_string(sha256_of_password, SHA256_DIGEST_LENGTH, &hex_hash);

    sprintf(sql, "INSERT INTO users (user_name, password) VALUES('%s','%s')",user_name, hex_hash);
    
    if( sqlite3_exec(db, sql, 0, 0, &errmssg) != SQLITE_OK )
    {
	fprintf(stderr, "SQL error: %s\n", errmssg);     
    }

    printf("%s\n", "SHA256 of the password was added to database.");
    free(hex_hash);
}

int registrate_user(SSL* ssl, char* username)
{
    int busy;
    char user_name [20] = { 0 };
    char password  [20] = { 0 };

    SSL_read(ssl, user_name, 20);
    printf("Username - %s\n",user_name);
    
    while ( (busy = lookup_for_username(user_name)) == 1)
    {
	memset(user_name, 0, 20);
	send_buff(ssl, "1", 1);
	receive_buff(ssl,user_name,20);
    }
    
    send_buff(ssl,"0",1);

    //demand password

    SSL_read(ssl,password,20);
    send_buff(ssl,"0",1);
    printf("Password received.\n");

    insert_username_password_to_db(user_name, password);
    strcpy(username, user_name);
    return 0;
}

int check_user_name_and_password_AUX(void* pass_ok, int argc, char** argv, char** azColName)
{   
    struct password_and_ok* p_ok = (struct password_and_ok*) pass_ok;

    char* SHA256_of_password = *argv;
    unsigned char sha256[SHA256_DIGEST_LENGTH] = { 0 };
    
    char* hex_sha256;
   
    SHA256(p_ok->password, strlen(p_ok->password), sha256);
    string_to_hex_string(sha256, SHA256_DIGEST_LENGTH, &hex_sha256);
    
    if(strcmp(hex_sha256, SHA256_of_password) == 0) //passwordes match
    {
	p_ok->ok = 1;
	return 1;
    }
    
    free(hex_sha256);
    free(SHA256_of_password);
    return -1;
}

int check_user_name_and_password(const char* user_name, const char* Password)
{
    char sql[200] = { 0 };
    struct password_and_ok pass;
    char* errmssg = 0;
    
    pass.ok = -1;
    pass.password = Password;

    sprintf(sql, "SELECT password FROM users WHERE user_name = '%s'", user_name);
    
    if( sqlite3_exec(db, sql, check_user_name_and_password_AUX, &pass, &errmssg) != SQLITE_OK)
    {	
	fprintf(stderr, "SQL error: %s\n", errmssg);
    }

    if(pass.ok == -1)
    {
	return -1; //wrong password
    }

    if(pass.ok == 1)
    {
	return 1; //right password
    }
}

int signin_user(SSL* ssl, char* username)
{
    char user_name[20] = { 0 };
    char password [20] = { 0 };

    receive_buff(ssl, user_name, 20);
    receive_buff(ssl, password, 20);

    printf("username: %s, password: %s\n", user_name, password);
    
    int ok = check_user_name_and_password(user_name, password);

    printf( "%s",  ok == -1 ? "Wrong password.\n": "Right password.\n");
    
    if(ok == 1)
    {
	strcpy(username, user_name);
    }

    return ok == -1 ? -1 : 1;
}

int authorize_client(SSL* ssl, char* user_name)
{
	char reg_or_log[2] = { 0 };
	SSL_write(ssl, "Authorize!", 10);
	
	SSL_read(ssl, reg_or_log, 2);
	printf("%s\n", atoi(reg_or_log) == 0 ? "registration" : "sign in" );

	if( atoi(reg_or_log) == 0 ) // registration
	{
	    registrate_user( ssl, user_name );
	    printf("Registration succeed.\n");
	}

	if( atoi(reg_or_log) == 1 ) // signing in
	{
	    while( signin_user( ssl, user_name ) == -1 )
	    {
		send_buff(ssl,"Wrong!",6);
	    }

	    send_buff(ssl,"Right!",6);
	}
}

void* connection_handler(void* cl_args)
{
	struct handler_args* args = (struct handler_args*) cl_args;
	char request_message[DATA_SIZE] = { 0 };
	int bytes_read;
	
	SSL_library_init();
	args->ctx = init_server_ctx();
        load_certificates(args->ctx,"mycert.pem","mycert.pem");
	
	SSL* ssl;	
	ssl = SSL_new(args->ctx);
	SSL_set_fd(ssl,args->socket);

	if( SSL_accept(ssl) == FAIL )
	{
	    ERR_print_errors_fp(stderr);
	    pthread_exit(NULL);
	}	
	else
	{
	    char user_name[20] = { 0 };
	    printf("\n%s\n","SSL connection established.");	    
	    // ShowCerts(ssl);  	   
	   
	    //demand authorization
	    authorize_client(ssl,user_name);
   
	    while ( (bytes_read = read_request(ssl, request_message)) > 0 )
	    {

			struct request_t request;
			fptr func;

			printf("Client's request : %s\n", request_message);
			memset(request_message, 0, DATA_SIZE);

			if( send_services(ssl) == 1 )
			{
				SSL_free(ssl);
				fprintf(stderr, "%s\n", strerror(errno));
				pthread_exit(NULL);
			}
				
			bytes_read = read_request(ssl, request_message);
			
			if (bytes_read <= 0)
			{
				break;
			}   	
			
			order_parser(request_message, &request);

			fprintf(stderr,"\nClient responsed\nquery: %s : %d\n", request.query, request.size);

			choose_corresponding_service(atoi(request.query), &request);
		
			if( valueForKeyInHashTable(ht, request.query, &func) == 0)
			{
				fprintf(stdout, "Could not find request: %s\n", request.query);
				pthread_exit(NULL);
			}

			func(request.size, ssl, user_name);
		    
			memset(request_message, 0, DATA_SIZE);
	    }
	    
	    SSL_free(ssl);
	    close(args->socket);
	    SSL_CTX_free(args->ctx);
	    fprintf(stdout, "Client disconnected. All resources freed\n");
	    pthread_exit(NULL);

	}
}

void print_usage(FILE* stream, int exit_code)
{
	fprintf (stream, "Usage: %s options [ inputfile .... ]\n", program_name);
	fprintf (stream,
			" -h --help	    Display this usage information.\n"
			" -c --conf	    filepath read parameters from file.\n"
			);
	exit (exit_code);
}

void sigpipe_handler(int signum)
{
	fprintf(stderr, "%s\n","Recevied SIGPIPE signal from a client, the thread exits.");
	pthread_exit(NULL);
}

void sigint_handler(int signum)
{
	sqlite3_close(db);
	fprintf(stderr, "%s\n", "Received SIGINT. All resources freed.");
	exit(EXIT_FAILURE);
}
