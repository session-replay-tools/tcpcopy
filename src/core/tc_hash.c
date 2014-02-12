
#include <xcopy.h>

static hash_node *
hash_node_malloc(uint64_t key, void *data)
{
    hash_node *hn = (hash_node *) malloc(sizeof(hash_node));

    if (hn == NULL) {
        tc_log_info(LOG_ERR, errno, "can't malloc memory for hash node");
        return NULL;
    }

    hn->key  = key;
    hn->data = data;
    hn->access_time = tc_time();
    hn->visit_cnt   = 0;

    return hn;
}

static p_link_node
hash_find_node(hash_table *table, uint64_t key)
{
    bool         first = true;
    hash_node   *hn;
    link_list   *l  = get_link_list(table, key);
    p_link_node  ln  = link_list_first(l);

    table->total_visit++;

    while (ln) {

        hn = (hash_node *) ln->data;
        table->total_key_compared++;
        if (hn->key == key) {
            hn->access_time = tc_time();
            hn->visit_cnt++;
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
hash_create(size_t size)
{
    size_t      i;
    hash_table *ht = (hash_table *) calloc(1, sizeof(hash_table));

    if (ht == NULL) {
        tc_log_info(LOG_ERR, errno, "can't calloc memory for hash table");
        return NULL;
    }

    ht->size  = size;
    ht->lists = (link_list **) calloc(size, sizeof(link_list *));
    if (ht->lists == NULL) {
        free(ht);
        tc_log_info(LOG_ERR, errno, "can't calloc memory for hash lists");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        ht->lists[i] = link_list_create();
    }

    ht->timeout = DEFAULT_TIMEOUT;

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
hash_add(hash_table *table, uint64_t key, void *data)
{
    hash_node   *hn, *tmp;
    link_list   *l;
    p_link_node  ln;

    ln = hash_find_node(table, key);
    if (ln != NULL) {
        hn = (hash_node *) ln->data;
        hn->data = data;
        return false;

    } else {
        tmp = hash_node_malloc(key, data);
        if (tmp == NULL) {
            return false;
        }
        ln  = link_node_malloc(tmp);
        if (ln == NULL) {
            return false;
        }
        l   = get_link_list(table, key);
        link_list_push(l, ln);
        table->total++;
        return true;
    }
}

bool
hash_del(hash_table *table, uint64_t key)
{
    link_list   *l = get_link_list(table, key);
    p_link_node ln = hash_find_node(table, key);

    if (ln != NULL) {
        table->total--;
        link_list_remove(l, ln);
        link_node_internal_free(ln);
        free(ln);

        return true;
    } else {

        return false;
    }
}

void
hash_set_timeout(hash_table *table, int t)
{
    table->timeout = t;
}

void
hash_destroy(hash_table *table)
{
    int         count = 0;
    uint32_t    index = 0;
    link_list  *l;

    for (; index < table->size; index++) {
        l = table->lists[index];
        if (l != NULL) {
            count += link_list_clear(l);
            free(l);
        }
    }

    free(table->lists);

    tc_log_info(LOG_NOTICE, 0, "total visit hash_find_node:%llu,compared:%llu",
                table->total_visit, table->total_key_compared);
    tc_log_info(LOG_NOTICE, 0, "destroy items %d in table name:%s",
                count, table->name);
}

void
hash_deep_destroy(hash_table *table)
{
    uint32_t      index = 0;
    hash_node    *hn;
    link_list    *l;
    p_link_node   ln, tmp_ln;

    for (; index < table->size; index++) {

        l = table->lists[index];
        if (l != NULL) {
            ln   = link_list_first(l);
            while (ln) {
                tmp_ln = link_list_get_next(l, ln);
                hn = (hash_node *) ln->data;
                if (hn->data != NULL) {
                    free(hn->data);
                    hn->data = NULL;
                }
                ln = tmp_ln;
            }
        }
    }

    hash_destroy(table);
}

