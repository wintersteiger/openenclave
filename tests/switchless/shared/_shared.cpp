#include "shared.h"
//#include <openenclave/internal/error.h>
//#include <openenclave/internal/tests.h>

void init_thread_control(
    thread_control* ptc,
    thread_control::STATE state,
    size_t count_limit)
{
    ptc->state = state;
    ptc->count_limit = count_limit;
    init_lockless_queue(&(ptc->enc_queue));
    init_lockless_queue(&(ptc->host_queue));
//    ptc->enc_push_queue = nullptr;
//    ptc->enc_pop_queue = nullptr;
//    ptc->host_push_queue = nullptr;
//    ptc->host_pop_queue = nullptr;
}

// this push operation uses an atomic compare_exchange_strong to allow for
// concurrent threads to push to the queue safely
void push_enc_queue(thread_control* ptc, queue_node* pnode)
{
    lockless_queue_push(&(ptc->enc_queue), &(pnode->_node));
//    queue_node* plink = nullptr;
//    do {
//        pnode->plink = plink = ptc->enc_push_queue;
//    } while (!ptc->enc_push_queue.compare_exchange_strong(plink, pnode));
}

// this pop operation allows for a single thread to pop from the queue while
// concurrent threads push to the queue
// it is not safe for concurrent threads to pop from the queue
queue_node* pop_enc_queue(thread_control* ptc)
{
    return (queue_node*)lockless_queue_pop(&(ptc->enc_queue));
//    // check if there are nodes on the pop queue
//    queue_node* pnode = ptc->enc_pop_queue;
//    if (nullptr != pnode)
//    {
//        ptc->enc_pop_queue.store(pnode->plink.load());
//        pnode->plink = nullptr;
//    }
//    else
//    {
//        // there are not nodes on the pop queue
//        // snatch any nodes off of the push queue if there are any
//        pnode = ptc->enc_push_queue;
//        if (nullptr != pnode)
//        {
//            // it is possible for new nodes to be pushed to the queue during
//            // this operation
//            // in order to handle that case
//            // a compare_exchange_strong operation is used
//            while (!ptc->enc_push_queue.compare_exchange_strong(pnode, nullptr))
//            {
//                pnode = ptc->enc_push_queue;
//            }
//
//            // pnode points to one or more nodes that are now isolated to this
//            // thread
//            // these nodes need to be reversed and put onto the pop queue
//            queue_node* pa = nullptr;
//            queue_node* pc = pnode->plink;
//            while (nullptr != pc) // todo, figure out the end condition
//            {
//                pnode->plink = pa;
//                pa = pnode;
//                pnode = pc;
//                pc = pc->plink;
//            }
//
//            // the nodes are now reversed
//            // insert the nodes onto the pop queue
//            ptc->enc_pop_queue = pa;
//
//            // clear the link from pnode
//            pnode->plink = nullptr;
//        }
//    }
//
//    return pnode;
}

// this push operation uses an atomic compare_exchange_strong to allow for
// concurrent threads to push to the queue safely
void push_host_queue(thread_control* ptc, queue_node* pnode)
{
    lockless_queue_push(&(ptc->host_queue), &(pnode->_node));
//    queue_node* plink = nullptr;
//    do {
//        pnode->plink = plink = ptc->host_push_queue;
//    } while (!ptc->host_push_queue.compare_exchange_strong(plink, pnode));
}

// this pop operation allows for a single thread to pop from the queue while
// concurrent threads push to the queue
// it is not safe for concurrent threads to pop from the queue
queue_node* pop_host_queue(thread_control* ptc)
{
    return (queue_node*)lockless_queue_pop(&(ptc->host_queue));
//    // check if there are nodes on the pop queue
//    queue_node* pnode = ptc->host_pop_queue;
//    if (nullptr != pnode)
//    {
//        ptc->host_pop_queue.store(pnode->plink.load());
//        pnode->plink = nullptr;
//    }
//    else
//    {
//        // there are not nodes on the pop queue
//        // snatch any nodes off of the push queue if there are any
//        pnode = ptc->host_push_queue;
//        if (nullptr != pnode)
//        {
//            // it is possible for new nodes to be pushed to the queue during
//            // this operation
//            // in order to handle that case
//            // a compare_exchange_strong operation is used
//            while (!ptc->host_push_queue.compare_exchange_strong(
//                       pnode, nullptr))
//            {
//                pnode = ptc->host_push_queue;
//            }
//
//            // pnode points to one or more nodes that are now isolated to this
//            // thread
//            // these nodes need to be reversed and put onto the pop queue
//            queue_node* pa = nullptr;
//            queue_node* pc = pnode->plink;
//            while (nullptr != pc) // todo, figure out the end condition
//            {
//                pnode->plink = pa;
//                pa = pnode;
//                pnode = pc;
//                pc = pc->plink;
//            }
//
//            // the nodes are now reversed
//            // insert the nodes onto the pop queue
//            ptc->host_pop_queue = pa;
//
//            // clear the link from pnode
//            pnode->plink = nullptr;
//        }
//    }
//
//    return pnode;
}
