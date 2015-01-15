//
// queue.h
//
// Created by Jaewon Seo.
//

#ifndef ProtocolClient_queue_h
#define ProtocolClient_queue_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef char* QUEUE_DATA;

typedef struct {
	QUEUE_DATA * data;
	int front;
	int rear;
	int max_size;
} QUEUE_T;

void queue_init(QUEUE_T *queue, int size);
void queue_push(QUEUE_T *queue, QUEUE_DATA val, int size);
void queue_pop(QUEUE_T *queue);
QUEUE_DATA queue_front(QUEUE_T *queue);
QUEUE_DATA queue_back(QUEUE_T *queue);
QUEUE_DATA queue_at(QUEUE_T *queue, int pos);
int queue_size(QUEUE_T *queue);

#endif