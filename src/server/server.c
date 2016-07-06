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
	request->filesize = atoi(token);
}

void set_hash_table()
{
	createHashTable(HTABLE_SIZE, &ht);
	addToHashTable(ht,"symmetric_key",add_symmetric_key_to_db_send_id);
	addToHashTable(ht,"compute_file_hash", receive_file_compute_hash_send_back);
	addToHashTable(ht,"AESencr_decr", AESencryption_decryption);
	//addToHashTable(ht,"add_symmetric_key_to_db_send_id", add_symmetric_key_to_db_send_id);
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

	}

}
void* connection_handler(void* cl_args)
{
	struct handler_args* args = (struct handler_args*) cl_args;
	char request_message[DATA_SIZE];
	int bytes_read;

	SSL* ssl;

	ssl = SSL_new(args->ctx);
	SSL_set_fd(ssl,args->socket);

	if( SSL_accept(ssl) == FAIL )
	{
	    ERR_print_errors_fp(stderr);
	}

	else
	{
	   // ShowCerts(ssl);
	    sqlite3* db;

	    printf("\n%s\n","SSL connection established with client");
	    sqlite3_open("SERVER_DB.dblite", &db);
	    fill_garbage_entry(&db, args->client_id);
	    
	    while ( (bytes_read = read_request(ssl, request_message)) > 0 )
	    {
			printf("Client's request : %s\n", request_message);
			memset(request_message, 0, DATA_SIZE);

			if( send_services(ssl) == 1 )
			{
				fprintf(stderr, "%s\n", strerror(errno));
				pthread_exit(NULL);
			}

			fptr func;

			struct request_t request;
					
			bytes_read = read_request(ssl, request_message);
			
			if (bytes_read == 0)
			{
				fprintf(stdout, "Client disconnected\n");
				pthread_exit(NULL);
			}	
			
			order_parser(request_message, &request);

			fprintf(stderr,"\nClient responsed\nquery: %s : %d\n", request.query, request.filesize);

			choose_corresponding_service(atoi(request.query), &request);
		
			if( valueForKeyInHashTable(ht, request.query, &func) == 0)
			{
				fprintf(stdout, "Could not find request: %s\n", request.query);
				pthread_exit(NULL);
			}

			printf("\nsize %d\n", request.filesize);
			
			func(request.filesize, ssl, &(args->client_id));

			memset(request_message, 0, DATA_SIZE);
	    }

	    fprintf(stdout, "Client disconnected\n");

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

void handler(int signum)
{
	printf("%s\n","Recevied SIGPIPE signal from a client, the thread exits");
	pthread_exit(NULL);
}
