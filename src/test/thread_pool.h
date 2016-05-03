#ifndef THREAD_POOL
#define THREAD_POOL

struct job_t {
    struct job_t *next;
    int socket_fd;
    char* buf;
};

typedef struct job_t job_t;
void initialize_jobs();

void create_pool();

void add_job(job_t* job);

job_t* remove_job();

int read_from_net();

job_t* get_job();

void process_job(job_t* job);
    
void* producer(void*);

void* consumer(void*);

#endif
