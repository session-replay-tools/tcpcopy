#include <xcopy.h>



static inline void tc_rbtree_left_rotate(tc_rbtree_node_t **root,
    tc_rbtree_node_t *sentinel, tc_rbtree_node_t *node);
static inline void tc_rbtree_right_rotate(tc_rbtree_node_t **root,
    tc_rbtree_node_t *sentinel, tc_rbtree_node_t *node);


void
tc_rbtree_insert(tc_rbtree_t *tree,
    tc_rbtree_node_t *node)
{
    tc_rbtree_node_t  **root, *temp, *sentinel;


    root = (tc_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (*root != sentinel) {
        tree->insert(*root, node, sentinel);

        while (node != *root && tc_rbt_is_red(node->parent)) {

            if (node->parent == node->parent->parent->left) {
                temp = node->parent->parent->right;

                if (tc_rbt_is_red(temp)) {
                    tc_rbt_black(node->parent);
                    tc_rbt_black(temp);
                    tc_rbt_red(node->parent->parent);
                    node = node->parent->parent;

                } else {
                    if (node == node->parent->right) {
                        node = node->parent;
                        tc_rbtree_left_rotate(root, sentinel, node);
                    }

                    tc_rbt_black(node->parent);
                    tc_rbt_red(node->parent->parent);
                    tc_rbtree_right_rotate(root, sentinel, 
                            node->parent->parent);
                }

            } else {
                temp = node->parent->parent->left;

                if (tc_rbt_is_red(temp)) {
                    tc_rbt_black(node->parent);
                    tc_rbt_black(temp);
                    tc_rbt_red(node->parent->parent);
                    node = node->parent->parent;

                } else {
                    if (node == node->parent->left) {
                        node = node->parent;
                        tc_rbtree_right_rotate(root, sentinel, node);
                    }

                    tc_rbt_black(node->parent);
                    tc_rbt_red(node->parent->parent);
                    tc_rbtree_left_rotate(root, sentinel, node->parent->parent);
                }
            }
        }

        tc_rbt_black(*root);

    } else {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        tc_rbt_black(node);
        *root = node;
    }

}


void
tc_rbtree_insert_value(tc_rbtree_node_t *temp, tc_rbtree_node_t *node,
    tc_rbtree_node_t *sentinel)
{
    tc_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    tc_rbt_red(node);
}


void
tc_rbtree_insert_timer_value(tc_rbtree_node_t *temp, tc_rbtree_node_t *node,
    tc_rbtree_node_t *sentinel)
{
    tc_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((tc_rbtree_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    tc_rbt_red(node);
}


void
tc_rbtree_delete(tc_rbtree_t *tree,
    tc_rbtree_node_t *node)
{
    tc_uint_t           red;
    tc_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;


    root = (tc_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        temp = node->left;
        subst = node;

    } else {
        subst = tc_rbtree_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    if (subst == *root) {
        *root = temp;
        tc_rbt_black(temp);

        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = tc_rbt_is_red(subst);

    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst == node) {

        temp->parent = subst->parent;

    } else {

        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        tc_rbt_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    if (red) {
        return;
    }

    /* a delete fixup */

    while (temp != *root && tc_rbt_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (tc_rbt_is_red(w)) {
                tc_rbt_black(w);
                tc_rbt_red(temp->parent);
                tc_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (tc_rbt_is_black(w->left) && tc_rbt_is_black(w->right)) {
                tc_rbt_red(w);
                temp = temp->parent;

            } else {
                if (tc_rbt_is_black(w->right)) {
                    tc_rbt_black(w->left);
                    tc_rbt_red(w);
                    tc_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                tc_rbt_copy_color(w, temp->parent);
                tc_rbt_black(temp->parent);
                tc_rbt_black(w->right);
                tc_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (tc_rbt_is_red(w)) {
                tc_rbt_black(w);
                tc_rbt_red(temp->parent);
                tc_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (tc_rbt_is_black(w->left) && tc_rbt_is_black(w->right)) {
                tc_rbt_red(w);
                temp = temp->parent;

            } else {
                if (tc_rbt_is_black(w->left)) {
                    tc_rbt_black(w->right);
                    tc_rbt_red(w);
                    tc_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                tc_rbt_copy_color(w, temp->parent);
                tc_rbt_black(temp->parent);
                tc_rbt_black(w->left);
                tc_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    tc_rbt_black(temp);
}


static inline void
tc_rbtree_left_rotate(tc_rbtree_node_t **root, tc_rbtree_node_t *sentinel,
    tc_rbtree_node_t *node)
{
    tc_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


static inline void
tc_rbtree_right_rotate(tc_rbtree_node_t **root, tc_rbtree_node_t *sentinel,
    tc_rbtree_node_t *node)
{
    tc_rbtree_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}
