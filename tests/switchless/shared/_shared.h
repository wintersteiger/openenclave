#ifndef _SHARED_H_
#define _SHARED_H_


#include <atomic>
#include <cstdlib>
#include "lockless_queue.h"


struct queue_node {
//    std::atomic<queue_node*> plink;
    lockless_queue_node _node;
    uint32_t function_id;
    uint8_t* args;
};


struct thread_control {

    enum STATE {
        RUNNING,
        STOPPING,
        STOPPED,
        EXITED,
    };
    
    std::atomic<STATE> state;
    size_t count_limit;

    lockless_queue enc_queue;
    lockless_queue host_queue;
//    std::atomic<queue_node*> enc_push_queue;
//    std::atomic<queue_node*> enc_pop_queue;
//    std::atomic<queue_node*> host_push_queue;
//    std::atomic<queue_node*> host_pop_queue;
};


void init_thread_control(
    thread_control* ptc,
    thread_control::STATE state = thread_control::EXITED,
    size_t count_limit = 0x06FFFFFF);


void push_enc_queue(thread_control* ptc, queue_node* pnode);
queue_node* pop_enc_queue(thread_control* ptc);


void push_host_queue(thread_control* ptc, queue_node* pnode);
queue_node* pop_host_queue(thread_control* ptc);


#endif // _SHARED_H_
