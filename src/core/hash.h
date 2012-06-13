#ifndef  _TCPCOPY_HASH_H_INC
#define  _TCPCOPY_HASH_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "xcopy.h"
#include "link_list.h"

#define DEFAULT_TIMEOUT   1200

	typedef struct hash_node_s{
		uint64_t key;
		time_t   access_time;
		void     *data;
	}hash_node_t, hash_node;

	typedef struct hash_table_s{
		uint32_t    total;
		uint32_t    size;
		int         timeout;
		char        name[64];
		link_list **lists;
	}hash_table_t, hash_table;

	hash_table *hash_create(size_t size);
	link_list_t *get_link_list(hash_table *table,uint64_t key);
	void hash_set_timeout(hash_table*,int);
	void hash_destory(hash_table*);
	void hash_add(hash_table*,uint64_t ,void *);
	void *hash_find(hash_table*,uint64_t);
	void hash_del(hash_table*,uint64_t);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_HASH_H_INC ----- */

