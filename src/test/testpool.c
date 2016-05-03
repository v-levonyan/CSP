#include "thread_pool.h"
#include <pthread.h>
#include <stdio.h>

int main()
{
    int rc;
    printf("start testing\n");
    create_pool();
    initialize_jobs();
    pthread_t /*thread_producer,*/ thread_consumer;
    /*
    if ( (rc = pthread_create(&thread_producer, NULL, producer, NULL)) ) {
	fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
	return 1;
    }*/
    pthread_create(&thread_consumer, NULL, consumer, NULL);

//    pthread_join(thread_producer, NULL);
    pthread_join(thread_consumer, NULL);

    return 0;
}
