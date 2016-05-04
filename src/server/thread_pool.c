#include "thread_pool.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#define THREAD_NUM 10

void* producer(void*);

struct job_t {
    struct job_t *next;
    int data;
};

typedef struct job_t job_t;

//globals
pthread_mutex_t mutex;
job_t *jobs;
sem_t jobs_count;
pthread_t threads[THREAD_NUM];

void initialize_jobs()
{
    jobs = NULL;
    pthread_mutex_init(&mutex, NULL);
    sem_init(&jobs_count, 0, 0);
}

void create_pool()
{
    int i;
    for(i = 0; i < THREAD_NUM; ++i)
    {
	pthread_create(&threads[i], NULL, producer, NULL);
    }
}

void add_job(job_t* job)
{
    pthread_mutex_lock(&mutex);
    job->next = jobs;
    jobs = job;
    pthread_mutex_unlock(&mutex);
}

job_t* remove_job()
{
    pthread_mutex_lock(&mutex);
    job_t* job = jobs;
    jobs = jobs->next;
    pthread_mutex_unlock(&mutex);
    return job;
}

int read_from_net()
{
    static int testcount = 0;
    testcount++;
    return testcount;
}

job_t* get_job()
{
    job_t* job;
    job = (job_t*) malloc(sizeof(job_t));
    job->data = read_from_net();
    return job;
}

void process_job(job_t* job)
{
    //process(job->data);
    free (job);
}
    
void* producer(void* arg)
{
    job_t *job;
    while(1)
    {
	job = get_job();
	add_job(job);
	sem_post(&jobs_count);
    }
}

void* consumer(void* arg)
{
    job_t* job;
    while(1)
    {
	sem_wait(&jobs_count);
	job = remove_job();
	process_job(job);
    }
}





