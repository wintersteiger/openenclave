#include "thread_control.h"


#if _MSC_VER
#include <Windows.h>
#endif


void init_thread_control(
    thread_control* ptc,
    uint32_t state,
    size_t count_limit)
{
    tc_set_state(ptc, state);
    ptc->count_limit = count_limit;
    init_lockless_queue(&(ptc->enc_queue));
    init_lockless_queue(&(ptc->host_queue));
}


uint32_t
tc_get_state(
    thread_control* ptc)
{
#ifdef _MSC_VER
    return InterlockedCompareExchange(&(ptc->_state), 0, 0);
#elif defined __GNUC__
    return __sync_val_compare_and_swap(&(ptc->_state), 0, 0);
#endif
}


void
tc_set_state(
    thread_control* ptc,
    uint32_t state)
{
#ifdef _MSC_VER
    InterlockedExchange(&(ptc->_state), state);
#elif defined __GNUC__
    uint32_t expect = 0;
    uint32_t actual = __sync_val_compare_and_swap(&(ptc->_state), expect, state);
    while (actual != expect)
    {
        expect = actual;
        actual = __sync_val_compare_and_swap(&(ptc->_state), expect, state);
    }
#endif
}


// this push operation uses an atomic compare_exchange_strong to allow for
// concurrent threads to push to the queue safely
void
tc_push_enc_queue(
    thread_control* ptc,
    queue_node* pnode)
{
    lockless_queue_push(&(ptc->enc_queue), &(pnode->_node));
}


// this pop operation allows for a single thread to pop from the queue while
// concurrent threads push to the queue
// it is not safe for concurrent threads to pop from the queue
queue_node*
tc_pop_enc_queue(
    thread_control* ptc)
{
    return (queue_node*)lockless_queue_pop(&(ptc->enc_queue));
}


// this push operation uses an atomic compare_exchange_strong to allow for
// concurrent threads to push to the queue safely
void
tc_push_host_queue(
    thread_control* ptc,
    queue_node* pnode)
{
    lockless_queue_push(&(ptc->host_queue), &(pnode->_node));
}


// this pop operation allows for a single thread to pop from the queue while
// concurrent threads push to the queue
// it is not safe for concurrent threads to pop from the queue
queue_node*
tc_pop_host_queue(
    thread_control* ptc)
{
    return (queue_node*)lockless_queue_pop(&(ptc->host_queue));
}
