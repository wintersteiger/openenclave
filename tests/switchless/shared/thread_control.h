#ifndef _THREAD_CONTROL_H_
#define _THREAD_CONTROL_H_


#include <stdint.h>
#include <stdlib.h>
#include "lockless_queue.h"


#ifndef EXTERN
#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN
#endif
#endif


#ifdef _MSC_VER
typedef uint32_t volatile state_t;
#elif defined __GNUC__
typedef uint32_t state_t;
#else
#error "unsupported"
#endif


typedef struct _queue_node {
    lockless_queue_node _node;
    uint32_t function_id;
    uint8_t* args;
} queue_node;


typedef struct _thread_control {
    enum {
        RUNNING,
        STOPPING,
        STOPPED,
        EXITED,
    };

    state_t _state;
    size_t count_limit;

    lockless_queue enc_queue;
    lockless_queue host_queue;
} thread_control;


EXTERN void
init_thread_control(
    thread_control* ptc,
    uint32_t state,
    size_t count_limit);


EXTERN uint32_t
tc_get_state(
    thread_control* ptc);


EXTERN void
tc_set_state(
    thread_control* ptc,
    uint32_t state);


EXTERN void
tc_push_enc_queue(
    thread_control* ptc,
    queue_node* pnode);


EXTERN queue_node*
tc_pop_enc_queue(
    thread_control* ptc);


EXTERN void
tc_push_host_queue(
    thread_control* ptc,
    queue_node* pnode);


EXTERN queue_node*
tc_pop_host_queue(
    thread_control* ptc);


#endif // _THREAD_CONTROL_H_
