
#include <xcopy.h>

p_link_node
link_node_malloc(void *data)
{
    p_link_node p;

    p = (p_link_node)calloc(1, sizeof(link_node));
    if (p == NULL) {
        return NULL;
    }
    p->data = data;

    return p;
}

link_list *
link_list_create()
{
    link_list *l = (link_list *) calloc(1, sizeof(link_list));

    if (l == NULL) {
        perror("calloc");
        return NULL;
    }
    l->size      = 0;
    l->head.next = &(l->head);
    l->head.prev = &(l->head);

    return l;
}

int
link_list_clear(link_list *l)
{
    int         count = 0;
    p_link_node p, next;

    p = l->head.next;
    while (p != &(l->head)) {
        next = p->next;
        count++;
        link_node_internal_free(p);
        free(p);
        p = next;
    }   

    l->head.next = &(l->head);
    l->head.prev = &(l->head);
    l->size = 0;

    return count;

}

/* append by order */
void
link_list_append_by_order(link_list *l, p_link_node p)
{
    p_link_node node, next;

    if (l->size > 0) {
        node = l->head.prev;
        next = node->next;
        /* find the node which key is less than the key of p */
        while (node->data != NULL && after(node->key, p->key)) {
            next = node;
            node = node ->prev;
        }
        node->next       = p;
        p->prev          = node;
        next->prev       = p;
        p->next          = next;
        l->size++;
    } else {
        link_list_append(l, p);
    }
}


