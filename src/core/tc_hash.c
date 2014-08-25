
#include <xcopy.h>

static hash_node *
hash_node_malloc(tc_pool_t *pool, uint64_t key, void *data)
{
    hash_node *hn = (hash_node *) tc_palloc(pool, sizeof(hash_node));

    if (hn != NULL) {
        hn->key  = key;
        hn->data = data;
    } else {
        tc_log_info(LOG_ERR, errno, "can't malloc memory for hash node");
    }

    return hn;
}


static p_link_node
hash_find_node(hash_table *table, uint64_t key)
{
    bool         first = true;
    hash_node   *hn;
    link_list   *l  = get_link_list(table, key);
    p_link_node  ln = link_list_first(l);

    while (ln) {

        hn = (hash_node *) ln->data;
        if (hn->key == key) {
            if (!first) {
                /* put the lastest item to the head of the linked list */
                link_list_remove(l, ln);
                link_list_push(l, ln);
            }
            return ln;
        }
        ln = link_list_get_next(l, ln);
        first = false;
    }

    return NULL;
}


hash_table *
hash_create(tc_pool_t *pool, uint32_t size)
{
    size_t      i;
    hash_table *ht = (hash_table *) tc_pcalloc(pool, sizeof(hash_table));

    if (ht != NULL) {
        ht->pool = pool;
        ht->size  = size;
        ht->lists = (link_list **) tc_pcalloc(pool, size * sizeof(link_list *));
        if (ht->lists != NULL) {
            for (i = 0; i < size; i++) {
                ht->lists[i] = link_list_create(pool);
            }
        } else {
            tc_log_info(LOG_ERR, errno, "can't calloc memory for hash lists");
            ht = NULL;
        }
    } else {
        tc_log_info(LOG_ERR, errno, "can't calloc memory for hash table");
    }

    return ht;
}


void *
hash_find(hash_table *table, uint64_t key)
{
    hash_node   *hn;
    p_link_node  ln = hash_find_node(table, key);

    if (ln != NULL) {
        hn = (hash_node *) ln->data;
        return hn->data;
    }

    return NULL;
}


bool
hash_add(hash_table *table, tc_pool_t *pool, uint64_t key, void *data)
{
    hash_node   *hn, *tmp;
    link_list   *l;
    p_link_node  ln;

    ln = hash_find_node(table, key);
    if (ln == NULL) {
        tmp = hash_node_malloc(pool, key, data);
        if (tmp != NULL) {
            l   = get_link_list(table, key);
            ln  = link_node_malloc(pool, tmp);
            if (ln != NULL) {
                link_list_push(l, ln);
                table->total++;
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        hn = (hash_node *) ln->data;
        hn->data = data;
        return false;
    }
}


bool
hash_del(hash_table *table, tc_pool_t *pool, uint64_t key)
{
    link_list  *l  = get_link_list(table, key);
    p_link_node ln = hash_find_node(table, key);

    if (ln != NULL) {
        table->total--;
        link_list_remove(l, ln);
        tc_pfree(pool, ln->data);
        tc_pfree(pool, ln);
        return true;
    } else {

        return false;
    }
}


