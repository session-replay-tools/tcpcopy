#include "../core/xcopy.h"

static uint64_t msg_item_cnt;
static uint64_t msg_item_free_cnt;
static uint64_t msg_item_destr_cnt;
static uint64_t msg_ll_cnt;
static uint64_t msg_ll_free_cnt;
static uint64_t msg_list_destr_cnt;

static hash_table  *table;

static struct msg_server_s *copy_message(struct msg_server_s *msg){
	struct msg_server_s *cmsg;
	cmsg=(struct msg_server_s *)malloc(sizeof(struct msg_server_s));
	if(NULL == cmsg){
		perror("malloc");
		log_info(LOG_ERR, "malloc error:%s", strerror(errno));
		sync(); 
		exit(EXIT_FAILURE);
	}
	memcpy(cmsg, msg, sizeof(struct msg_server_s));
	return cmsg;
}

static void delay_table_delete_obsolete(uint64_t key)
{
	hash_node   *hn1;
	hash_node   *hn2;
	p_link_node ln;
	link_list   *msg_list;
	time_t      nowtime = time(0);
	link_list   *l      = get_link_list(table,key);

	while(1){
		ln = link_list_tail(l);
		if(NULL == ln){
			break;
		}   
		hn1 = (hash_node *)ln->data;
		if( (hn1->access_time + table->timeout) < nowtime){
			p_link_node tail = link_list_pop_tail(l);
			hn2 = (hash_node *)tail->data;
			if(NULL != hn2)
			{   
				if(hn2->data != NULL)
				{
					msg_list = (link_list *)hn2->data;
					msg_item_destr_cnt += link_list_destory(msg_list);
					free(msg_list);  	
					hn2->data = NULL;
					msg_list_destr_cnt++;
				}
				free(hn2);
			}   
			tail->data = NULL;
			free(tail);
		}else{
			break;
		}   
	} 
}


/* init delay table */
void delay_table_init(){
	/* we support 64k slots here */
	table = hash_create(65536);
	hash_set_timeout(table, 30);
	strcpy(table->name,"delay-table");
	log_info(LOG_NOTICE,"create table %s,size:%u",
			table->name, table->size);
	msg_item_cnt       = 0;
	msg_item_free_cnt  = 0;
	msg_item_destr_cnt = 0;
	msg_ll_cnt         = 0;
	msg_list_destr_cnt = 0;
}

/* add message to delay table*/
void delay_table_add(uint64_t key,struct msg_server_s *msg){
	link_list           *msg_list;
	struct msg_server_s *cmsg;
	p_link_node         ln;

	delay_table_delete_obsolete(key);	
	msg_list =(link_list *)hash_find(table, key);
	cmsg = copy_message(msg);
	ln = link_node_malloc((void *)cmsg);
	if(NULL == msg_list){
		msg_ll_cnt++;
		msg_list = link_list_create();
		hash_add(table, key, msg_list);
	}
	msg_item_cnt++;
	link_list_append(msg_list, ln);
	return;
}


/* send delayed message according to the key*/
void delay_table_send(uint64_t key,int fd){
	link_list           *msg_list;
	p_link_node         first;
	struct msg_server_s *msg ;

	delay_table_delete_obsolete(key);	
	msg_list =(link_list *)hash_find(table, key);
	if(NULL == msg_list){
		return;	
	}
	while(! link_list_is_empty(msg_list)){
		first = link_list_pop_first(msg_list);
		msg = (first->data);
		(void)msg_server_send(fd, msg);
		if(msg != NULL)
		{
			free(msg);
		}
		msg_item_free_cnt++;
		link_node_free(first);
	}
}

/* delete delay table item according to the key */
void delay_table_del(uint64_t key){
	link_list           *msg_list;
	p_link_node         first;
	struct msg_server_s *msg;

	delay_table_delete_obsolete(key);	
	msg_list =(link_list *)hash_find(table, key);
	if(NULL == msg_list){
		return;	
	}
	while(! link_list_is_empty(msg_list)){
		first = link_list_pop_first(msg_list);
		msg = (first->data);
		if(msg != NULL)
		{
			free(msg);
		}
		msg_item_free_cnt++;
		link_node_free(first);
	}
	hash_del(table, key);
	free(msg_list);
	msg_ll_free_cnt++;
}

/* destroy delay table */
void delay_table_destroy()
{
	uint32_t    i;
	link_list   *msg_list;
	p_link_node ln;
	hash_node   *hn;
	link_list   *list;

	if(table != NULL)
	{
		log_info(LOG_NOTICE,"destroy delayed table");
		for(i = 0; i < table->size; i++)
		{
			list = table->lists[i];
			ln   = link_list_first(list);
			while(ln){
				hn = (hash_node *)ln->data;
				if(hn->data != NULL)
				{
					msg_list=(link_list *)hn->data;
					msg_item_destr_cnt+=link_list_destory(msg_list);
					free(msg_list);
					msg_list_destr_cnt++;
				}	
				hn->data = NULL;
				ln = link_list_get_next(list, ln);
			}
		}

		log_info(LOG_NOTICE,"destroy msg list items:%llu,free:%llu,total:%llu",
				msg_item_destr_cnt, msg_item_free_cnt, msg_item_cnt);
		log_info(LOG_NOTICE,"create msg list:%llu,free:%llu,destroyList:%llu",
				msg_ll_cnt, msg_ll_free_cnt, msg_list_destr_cnt);
		hash_destory(table);
		free(table);
		table = NULL;
	}
}

