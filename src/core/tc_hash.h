#ifndef  TC_HASH_INCLUDED
#define  TC_HASH_INCLUDED

#include <xcopy.h>

typedef struct hash_node_s{
    uint64_t    key;
    void       *data;
}hash_node_t, hash_node;

typedef struct hash_table_s{
    tc_pool_t  *pool;  
    link_list **lists;
    uint32_t    total;
    uint32_t    size;
}hash_table_t, hash_table;

hash_table *hash_create(tc_pool_t *pool, uint32_t size);

static inline uint32_t 
get_slot(uint64_t key, uint32_t size)
{
    uint32_t trim_key = key & (0xFFFFFFFF);

    return trim_key % size;
}


static inline link_list_t *
get_link_list(hash_table *table, uint64_t key)
{
    uint32_t slot = get_slot(key, table->size);
    return table->lists[slot];
}


bool hash_add(hash_table*, tc_pool_t*, uint64_t, void *);
void *hash_find(hash_table*, uint64_t);
bool hash_del(hash_table*, tc_pool_t*, uint64_t);

#endif /* TC_HASH_INCLUDED */

