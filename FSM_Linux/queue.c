//
// queue.c
//
// Created by Jaewon Seo.
//

#include "queue.h"

void queue_init(QUEUE_T *queue, int size)
{
    queue->front = 0;
    queue->rear = 0;
    queue->max_size = size;
    queue->data = malloc(sizeof(QUEUE_DATA) * size);
}

void queue_push(QUEUE_T *queue, QUEUE_DATA val, int size)
{
    if (queue_size(queue) + 1 >= queue->max_size)
        return;

    queue->rear = (queue->rear + 1) % queue->max_size;

    queue->data[queue->rear] = malloc(size);
    memcpy(queue->data[queue->rear], val, size);
}

void queue_pop(QUEUE_T *queue)
{
    if (queue_size(queue) <= 0)
        return;

    free(queue->data[queue->front]);
    queue->front = (queue->front + 1) % queue->max_size;
}

QUEUE_DATA queue_front(QUEUE_T *queue)
{
    if (!queue->data || queue_size(queue) == 0)
        return NULL;

    return queue->data[(queue->front + 1) % queue->max_size];
}

QUEUE_DATA queue_back(QUEUE_T *queue)
{   
    if (!queue->data || queue_size(queue) == 0)
        return NULL;

    return queue->data[queue->rear];
}

QUEUE_DATA queue_at(QUEUE_T *queue, int pos)
{
    if (!queue->data || pos >= queue_size(queue))
        return NULL;
    
    return queue->data[(queue->front + 1 + pos) % queue->max_size];
}

int queue_size(QUEUE_T *queue)
{
    if (queue->front == queue->rear)
        return 0;

    if (queue->front < queue->rear)
        return queue->rear - queue->front;
    else
        return queue->max_size - (queue->front - queue->rear);
}
