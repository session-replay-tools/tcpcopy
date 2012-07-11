#include "xcopy.h"
#include "hash.h"

static hash_node *hash_node_malloc(uint64_t key, void *data)
{
    hash_node *hn = (hash_node *)malloc(sizeof(hash_node));
    if(NULL == hn){
        perror("can't malloc memory!");
        log_info(LOG_ERR, "can't malloc memory for hash node:%s",
                strerror(errno));
        sync(); 
        exit(errno);
    }

    hn->key  = key;
    hn->data = data;
    hn->access_time = time(0);
    hn->visit_cnt   = 0;

    return hn;
}

static inline size_t get_slot(uint64_t key, size_t size)
{
    return key%size;
}

static p_link_node hash_find_node(hash_table *table, uint64_t key)
{
    link_list   *l  = get_link_list(table, key);
    p_link_node ln  = link_list_first(l);
    hash_node   *hn;
    table->total_visit++;
    while(ln){
        hn = (hash_node *)ln->data;
        table->total_key_compared++;
        if(hn->key == key){
            hn->access_time = time(0);
            hn->visit_cnt++;
            /* Put the lastest item to the head of the linked list */
            (void)link_list_remove(l, ln);
            link_list_push(l, ln);
            return ln;
        }
        ln = link_list_get_next(l, ln);
    }
    return NULL;
}

hash_table *hash_create(size_t size)
{
    size_t i;
    hash_table *ht = (hash_table *)calloc(1, sizeof(hash_table));
    if(NULL == ht){
        perror("can't calloc memory!");
        log_info(LOG_ERR, "can't calloc memory for hash table:%s",
                strerror(errno));
        sync(); 
        exit(errno);
    }
    ht->size  = size;
    ht->lists = (link_list **) calloc(size, sizeof(link_list *));
    if(NULL == ht->lists){
        perror("can't calloc memory!");
        log_info(LOG_ERR, "can't calloc memory for hash lists:%s",
                strerror(errno));
        sync(); 
        exit(errno);
    }
    for(i=0; i < size; i++){
        ht->lists[i] = link_list_create();
    }
    ht->timeout = DEFAULT_TIMEOUT;

    return ht;
}

inline link_list *get_link_list(hash_table *table, uint64_t key)
{
    size_t slot = get_slot(key, table->size);
    return table->lists[slot];
}

void *hash_find(hash_table *table, uint64_t key)
{
    hash_node   *hn;
    p_link_node ln = hash_find_node(table, key);
    if(ln != NULL){
        hn = (hash_node *) ln->data;
        return hn->data;
    }
    return NULL;
}

bool hash_add(hash_table *table, uint64_t key, void *data)
{
    hash_node   *hn, *tmp;
    p_link_node ln;
    link_list   *l;

    ln = hash_find_node(table, key);
    if(ln != NULL){
        hn = (hash_node *) ln->data;
        hn->data = data;
        return false;
    }else{
        tmp = hash_node_malloc(key, data);
        ln  = link_node_malloc(tmp);
        l   = get_link_list(table, key);
        link_list_push(l , ln);
        table->total++;
        return true;
    }
}

bool hash_del(hash_table *table, uint64_t key)
{
    link_list   *l = get_link_list(table, key); 
    p_link_node ln = hash_find_node(table, key);
    if(ln != NULL){
        table->total--;
        link_list_remove(l, ln);
        link_node_internal_free(ln);
        free(ln);
        return true;
    }else{
        return false;
    }
}

void hash_set_timeout(hash_table *table, int t)
{
    table->timeout = t;
}

void hash_destory(hash_table *table)
{
    uint32_t     index = 0;
    link_list    *l    = NULL;
    int          count = 0;
    for(; index < table->size; index++){
        l = table->lists[index];
        if(l != NULL){
            count += link_list_clear(l);
            free(l);
        }
    }
    free(table->lists);
    log_info(LOG_NOTICE, "total visit hash_find_node:%llu,compared:%llu",
            table->total_visit, table->total_key_compared);
    log_info(LOG_NOTICE, "destroy items %d in table name:%s",
            count, table->name);
}

