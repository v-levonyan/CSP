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
#include "hashtable.h"
#include "server.h"

#define DATA_SIZE 1024
#define HTABLE_SIZE 10

int send_file(int file_fd, int sock_fd)
{
	char buf[DATA_SIZE] = { 0 };

	while(1)
	{
		int num_read;
		char* p = buf;

		num_read = read(file_fd, buf, DATA_SIZE - 1);

		if(num_read < 0)
		{ 
			fprintf(stderr,"%s\n",strerror(errno));
			return 1;
		}

		if(num_read == 0)
		{
			break;
		}

		while(num_read > 0)
		{
			int num_write =  write(sock_fd, p, num_read);

			if(num_write < 0)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				return 1;
			}

			num_read -= num_write;
			p += num_write;
		}
	}

	return 0;
}

int send_services(int sock_fd)
{
	int file_fd;

	if( (file_fd = open("server/services.txt", O_RDONLY)) < 0)
	{
		fprintf(stderr, "%s", "couldn't open services.txt file");
		strerror(errno);
		return 1;
	}   

	if( send_file(file_fd, sock_fd) == 1)
	{
		return 1;
	}

	return 0;
}
void create_socket(int *socket_desc) 
{
	*socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if((*socket_desc) == -1)
	{
		handle_error("Could not create socket");
	}
	int enable = 1;
	if (setsockopt((*socket_desc), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
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

void compute_hash_file(size_t filesize, int* socket)
{
	fprintf(stderr, "entering compute hash.........\n");
	unsigned char hash[SHA_DIGEST_LENGTH] = { 0 };
	ssize_t bytes_read = 0;
	size_t remain_data = filesize;
	char data[DATA_SIZE] = { 0 };
	SHA_CTX ctx;
	SHA1_Init(&ctx);

	while( remain_data > 0 && (bytes_read = read(*socket, data, DATA_SIZE - 1)) )
	{
		remain_data -= bytes_read;

		if(bytes_read == -1)
		{
			handle_error("data wasn't read");
		}

		fprintf(stderr, "received file content: %s\n", data);

		SHA1_Update(&ctx, data, strlen(data));
		memset(data, 0, DATA_SIZE);
	}
	fprintf(stderr,"generating final hash");
	if( SHA1_Final(hash, &ctx) == 0)
	{		

		fprintf(stderr,"%s", "SHA final exits");
		pthread_exit(NULL);
	}
	write(*socket, hash, SHA_DIGEST_LENGTH);
}

struct request_t {
	char query[30];
	int filesize;
};

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
	addToHashTable(ht,"compute_file_hash",compute_hash_file);
}

int read_request(int* socket, char request[DATA_SIZE])
{
	memset(request, 0, DATA_SIZE);
	int read_size;
	read_size = read(*socket, request, DATA_SIZE);
	if(read_size < 0)
	{
		handle_error("Could not read from socket");
	//	fprintf(stderr, "%s\n", request);
	//	pthread_exit(NULL);
	}
	fprintf(stderr, "reading request: %s\n", request);
	return read_size;
}


void* connection_handler(void* sock_desc)
{
	char request_message[DATA_SIZE];
	int socket = *( (int*)sock_desc );
	int bytes_read;

	while ( (bytes_read = read_request(&socket, request_message)) > 0 )
	{
		printf("%s\n", request_message);

		if( send_services(socket) == 1 )
		{   
			fprintf(stderr, "%s\n", strerror(errno));
			pthread_exit(NULL);
		}

		fptr func;

		struct request_t request;

		bytes_read = read_request(&socket, request_message);
		if (bytes_read == 0)
		{
			fprintf(stdout, "Client disconnected");
			pthread_exit(NULL);
		}

		order_parser(request_message, &request);

		fprintf(stderr,"\nquery: %s, filesize: %d\n", request.query, request.filesize);


		if( valueForKeyInHashTable(ht, request.query, &func) == 0)
		{
			fprintf(stdout, "Could not find request: %s\n", request.query);
			pthread_exit(NULL);
		}

		func(request.filesize, &socket);
	}

	pthread_exit(NULL);

/*
	if (bytes_read == 0)
	{
		fprintf(stdout, "Client disconnected");
		pthread_exit(NULL);
	}
	*/
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
	return;
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
