#include "hash.h"
#include "linklist.h"
#include "../log/log.h"

static hash_node *hash_node_malloc(uint64_t key,void *data){
	hash_node * newnode = (hash_node *)malloc(sizeof(hash_node));
	if(! newnode){
		perror("cannot malloc memory!");
		logInfo(LOG_ERR,"can't malloc memory for hash node:%s",
				strerror(errno));
		sync(); 
		exit(errno);
	}
	newnode->key = key;
	newnode->data = data;
	newnode->access_time = time(NULL);
	return newnode;
}
static inline size_t   get_slot(uint64_t key,size_t size){
	return key%size;
}

hash_table *hash_create(size_t size){
	size_t i =0;
	hash_table * htable  = (hash_table *)malloc(sizeof(hash_table));
	if(! htable){
		perror("cannot malloc memory!");
		logInfo(LOG_ERR,"can't malloc memory for hash table:%s",
				strerror(errno));
		sync(); 
		exit(errno);
	}
	htable->size = size;
	htable->lists = (struct linklist **) malloc(sizeof(linklist *) *size);
	if(! htable->lists){
		perror("cannot malloc memory!");
		logInfo(LOG_ERR,"can't malloc memory for hash lists:%s",
				strerror(errno));
		sync(); 
		exit(errno);
	}
	for(i=0;i<size;i++){
		htable->lists[i] = linklist_create();
	}
	htable->timeout = DEFAULT_TIMEOUT;
	return htable;
}

linklist * get_linklist(hash_table *table,uint64_t key){
	size_t slot = get_slot(key,table->size);
	linklist *l = table->lists[slot];
	return l;
}

static lnodeptr  hash_find_node(hash_table *table,uint64_t key){
	linklist *l = get_linklist(table,key);
	hash_node *hnode =NULL;
	lnodeptr node = linklist_first(l);
	while(node){
		hnode = (hash_node *)node->data;
		if(hnode->key == key){
			hnode->access_time = time(NULL);
			/* put the lastest item to the head of the link list */
			(void)linklist_remove(node);
			linklist_push(l,node);
			return node;
		}
		node = linklist_get_next(l,node);
	}
	return NULL;
}

void * hash_find(hash_table *table,uint64_t key){
	hash_node *hnode=NULL;
	lnodeptr node = hash_find_node(table,key);
	if(node != NULL){
		hnode = (hash_node *) node->data;
		return hnode->data;
	}
	return NULL;
}

void hash_add(hash_table *table,uint64_t key,void *data){
	hash_node *hnode = NULL;
	hash_node *newnode =NULL;
	lnodeptr  pnode = NULL;
	linklist *l = NULL;
	lnodeptr node = hash_find_node(table,key);
	if(node != NULL){
		hnode = (hash_node *) node->data;
		hnode->data = data;
	}else
	{
		newnode = hash_node_malloc(key,data);
		pnode = lnode_malloc(newnode);
		l = get_linklist(table,key);
		linklist_push(l,pnode);
	}
}


void hash_del(hash_table *table,uint64_t key){
	lnodeptr node = hash_find_node(table,key);
	if(node != NULL){
		linklist_remove(node);
		if(node->data!=NULL)
		{
			free(node->data);
		}
		node->data=NULL;
		lnode_free(node);
	}
	return;
}

void hash_set_timeout(hash_table *table,int t){
	table->timeout = t;
}

void hash_destory(hash_table *table)
{
	uint32_t index=0;
	linklist* l=NULL;
	int count=0;
	for(;index<table->size;index++)
	{
		l=table->lists[index];
		if(l!=NULL)
		{
			count+=linklist_destory(l);
			free(l);
		}
	}
	free(table->lists);
	logInfo(LOG_NOTICE,"destroy items %d in table name:%s",
			count,table->name);
}

