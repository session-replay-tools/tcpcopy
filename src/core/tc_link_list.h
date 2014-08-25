#ifndef  TC_LINK_LIST_INCLUDED
#define  TC_LINK_LIST_INCLUDED

#include <xcopy.h>

typedef struct link_node_s
{
    struct link_node_s *prev;
    struct link_node_s *next;
    void     *data;
    uint32_t  key;
}link_node_t, link_node, *p_link_node;

typedef struct link_list_s{
    link_node head;
    int size;
}link_list_t, link_list;


p_link_node link_node_malloc(tc_pool_t *pool, void *data);
link_list *link_list_create(tc_pool_t *pool);
void link_list_append_by_order(link_list *l, p_link_node);


static inline void 
link_list_append(link_list *l, p_link_node p)
{
    p_link_node node;

    node         = l->head.prev;
    node->next   = p;
    p->prev      = node;
    l->head.prev = p;
    p->next      = &(l->head);
    l->size++;
}


static inline void 
link_list_push(link_list *l, p_link_node p)
{
    p_link_node node;

    node         = l->head.next;
    node->prev   = p;
    p->next      = node;
    l->head.next = p;
    p->prev      = &(l->head);
    l->size++;
}


static inline p_link_node 
link_list_remove(link_list *l, p_link_node node)
{
    p_link_node next, prev;

    next = node->next;
    prev = node->prev;
    next->prev = prev;
    prev->next = next;
    l->size--;
    return node;
}


static inline p_link_node 
link_list_first(link_list *l)
{
    if (l == NULL || l->head.next == &(l->head)) {
        return NULL;
    }

    return l->head.next;
}


static inline p_link_node 
link_list_tail(link_list *l)
{
    if (l == NULL || l->head.next == &(l->head)) {
        return NULL;
    }

    return l->head.prev;
}


static inline p_link_node
link_list_get_next(link_list *l, p_link_node p)
{
    if (p->next == &(l->head)) {
        return NULL;
    }

    return p->next;
} 

#endif /* TC_LINK_LIST_INCLUDED */

