#include "hash.h"
#include "delay.h"
#include "../log/log.h"

static hash_table  *table;
static int mCount;
static int lCount;
static int fCount;
static int delayDel;
static int lDestroy;
static int count;

static struct receiver_msg_st * copy_message(struct receiver_msg_st *msg){
	struct receiver_msg_st *cmsg = NULL;
	cmsg=(struct receiver_msg_st *)malloc(sizeof(struct receiver_msg_st));
	if(NULL == cmsg){
		perror("malloc");
		logInfo(LOG_ERR,"malloc error");
		exit(EXIT_FAILURE);
	}
	memcpy(cmsg,msg,sizeof(struct receiver_msg_st));
	return cmsg;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  delay_table_init
 *  Description:  init delay table
 * =====================================================================================
 */
void delay_table_init(){
	/* we support 64k slots here */
	table = hash_create(1024*64);
	hash_set_timeout(table,30);
	strcpy(table->name,"delay-table");
	logInfo(LOG_NOTICE,"create table %s,size:%u",table->name,table->size);
	mCount=0;
	fCount=0;
	lCount=0;
	delayDel=0;
	lDestroy=0;
	count=0;
}

static void delay_table_delete_obsolete(uint64_t key)
{
	linklist *l = get_linklist(table,key);
	time_t  nowtime = time(0);
	hash_node *hnode1=NULL;
	hash_node *hnode2=NULL;
	lnodeptr node=NULL;

	while(1){
		node = linklist_tail(l);
		if(! node ){
			break;
		}   
		hnode1 = (hash_node *)node->data;
		if(hnode1->access_time+table->timeout < nowtime){
			lnodeptr tail=linklist_pop_tail(l);
			hnode2 = (hash_node *)tail->data;
			if(NULL!=hnode2)
			{   
				if(hnode2->data!=NULL)
				{
					linklist *msg_list=(linklist *)hnode2->data;
					count+=linklist_destory(msg_list);
					free(msg_list);  	
					hnode2->data=NULL;
					lDestroy++;
				}
				free(hnode2);
			}   
			tail->data=NULL;
			free(tail);
		}else{
			break;
		}   
	} 
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  delay_table_add
 *  Description:  add msg to delay table
 * =====================================================================================
 */
void delay_table_add(uint64_t key,struct receiver_msg_st *msg){
	linklist *msg_list=NULL;
	struct receiver_msg_st *cmsg = NULL;
	lnodeptr pnode=NULL;

	delay_table_delete_obsolete(key);	
	msg_list =(linklist *)hash_find(table,key);
	cmsg = copy_message(msg);
	pnode = lnode_malloc((void *)cmsg);
	if(NULL == msg_list){
		lCount++;
		msg_list = linklist_create();
		hash_add(table,key,msg_list);
	}
	mCount++;
	linklist_append(msg_list,pnode);
	return;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  delay_table_send
 *  Description:  send delayed message according key
 * =====================================================================================
 */
void delay_table_send(uint64_t key,int fd){
	linklist *msg_list=NULL;
	struct receiver_msg_st *msg=NULL;
	lnodeptr first=NULL;

	delay_table_delete_obsolete(key);	
	msg_list =(linklist *)hash_find(table,key);
	if(NULL == msg_list){
		return;	
	}
	while(! linklist_is_empty(msg_list)){
		first = linklist_pop_first(msg_list);
		msg = (first->data);
		(void)msg_receiver_send(fd,msg);
		if(msg != NULL)
		{
			free(msg);
		}
		fCount++;
		lnode_free(first);
	}
}

void delay_table_del(uint64_t key){
	linklist *msg_list=NULL;
	struct receiver_msg_st *msg=NULL;
	lnodeptr first=NULL;

	delay_table_delete_obsolete(key);	
	msg_list =(linklist *)hash_find(table,key);
	if(NULL == msg_list){
		return;	
	}
	while(! linklist_is_empty(msg_list)){
		first = linklist_pop_first(msg_list);
		msg = (first->data);
		if(msg!=NULL)
		{
			free(msg);
		}
		delayDel++;
		fCount++;
		lnode_free(first);
	}
	hash_del(table,key);
	free(msg_list);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  delay_table_destroy
 *  Description:  destroy delay table
 * =====================================================================================
 */
void delay_table_destroy()
{
	uint32_t i=0;
	linklist* list=NULL;
	linklist *msg_list=NULL;
	lnodeptr node=NULL;
	hash_node *hnode=NULL;

	if(table!=NULL)
	{
		logInfo(LOG_NOTICE,"destroy delayed table");
		for(;i<table->size;i++)
		{
			list=table->lists[i];
			node = linklist_first(list);
			while(node){
				hnode = (hash_node *)node->data;
				if(hnode->data!=NULL)
				{
					msg_list=(linklist *)hnode->data;
					count+=linklist_destory(msg_list);
					free(msg_list);
					lDestroy++;
				}	
				hnode->data=NULL;
				node = linklist_get_next(list,node);
			}
		}

		logInfo(LOG_NOTICE,"destroy msg list items:%d,free:%d,total:%d",
				count,fCount,mCount);
		logInfo(LOG_NOTICE,"create msg list:%d,delayDel:%d,destroyList:%d",
				lCount,delayDel,lDestroy);
		hash_destory(table);
		free(table);
		table=NULL;
	}
}

