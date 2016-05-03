#include "thread_pool.h"
#include "server.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#define THREAD_NUM 10



//globals
pthread_mutex_t mutex;
job_t *jobs;
sem_t jobs_count;
sem_t jobs_slots;
pthread_t threads[THREAD_NUM];

void initialize_jobs()
{
    jobs = NULL;
    pthread_mutex_init(&mutex, NULL);
    sem_init(&jobs_count, 0, 0);
    sem_init(&jobs_slots, 0, THREAD_NUM);
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

job_t* get_job(int socket_fd)
{
    job_t* job;
    char ibuf[100];

    read(socket_fd, ibuf, 50);
    if(strcmp(ibuf, "End") == 0)
    {
	return NULL;
    }
    job = (job_t*) malloc(sizeof(job_t));
    job->socket_fd = socket_fd;
    job->buf = (char*) malloc(strlen(ibuf) + 1);
    strcpy(job->buf, ibuf);
    return job;
}


void process_job(job_t* job)
{
    int sock = job->;
    free (job);
}
    
void producer(int socket_fd)
{
    job_t *job;
    while(1)
    {
	job = get_job(socket_fd);
	if (job == NULL) {
	    return;
	}

	sem_wait(&jobs_slots);
	add_job(job);
	sem_post(&jobs_count);
    }
}

void* accept_jobs(void *socket_desc)
{
    int socket_fd = *((int*) socket_desc);
    producer(socket_fd);
    write(socket_fd, "End", 4);
    close(socket_fd);
    pthread_exit(NULL);
}


void* consumer(void* arg)
{
    job_t* job;
    while(1)
    {
	sem_wait(&jobs_count);
	job = remove_job();
	process_job(job);
	sem_post(&jobs_slots);
    }
}





