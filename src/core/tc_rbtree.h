#ifndef _TC_RBTREE_H_INCLUDED_
#define _TC_RBTREE_H_INCLUDED_


#include <xcopy.h>


typedef tc_uint_t  tc_rbtree_key_t;
typedef tc_int_t   tc_rbtree_key_int_t;


typedef struct tc_rbtree_node_s  tc_rbtree_node_t;

struct tc_rbtree_node_s {
    tc_rbtree_key_t       key;
    tc_rbtree_node_t     *left;
    tc_rbtree_node_t     *right;
    tc_rbtree_node_t     *parent;
    u_char                color;
    u_char                data;
};


typedef struct tc_rbtree_s  tc_rbtree_t;

typedef void (*tc_rbtree_insert_pt) (tc_rbtree_node_t *root,
    tc_rbtree_node_t *node, tc_rbtree_node_t *sentinel);

struct tc_rbtree_s {
    tc_rbtree_node_t     *root;
    tc_rbtree_node_t     *sentinel;
    tc_rbtree_insert_pt   insert;
};


#define tc_rbtree_init(tree, s, i)                                           \
    tc_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                        \
    (tree)->sentinel = s;                                                    \
    (tree)->insert = i


void tc_rbtree_insert(tc_rbtree_t *tree,
    tc_rbtree_node_t *node);
void tc_rbtree_delete(tc_rbtree_t *tree,
    tc_rbtree_node_t *node);
void tc_rbtree_insert_value(tc_rbtree_node_t *root, tc_rbtree_node_t *node,
    tc_rbtree_node_t *sentinel);
void tc_rbtree_insert_timer_value(tc_rbtree_node_t *root,
    tc_rbtree_node_t *node, tc_rbtree_node_t *sentinel);


#define tc_rbt_red(node)               ((node)->color = 1)
#define tc_rbt_black(node)             ((node)->color = 0)
#define tc_rbt_is_red(node)            ((node)->color)
#define tc_rbt_is_black(node)          (!tc_rbt_is_red(node))
#define tc_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define tc_rbtree_sentinel_init(node)  tc_rbt_black(node)


static inline tc_rbtree_node_t *
tc_rbtree_min(tc_rbtree_node_t *node, tc_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _TC_RBTREE_H_INCLUDED_ */
