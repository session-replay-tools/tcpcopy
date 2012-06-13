#ifndef  _LINK_LIST_H_INC
#define  _LINK_LIST_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct link_node_s
	{
		struct link_node *prev;
		struct link_node *next;
		void   *data;
		uint32_t key;
	}link_node_t, link_node, *p_link_node;

	typedef struct link_list_s{
		link_node head;
		int size;
	}link_list_t, link_list;


	p_link_node link_node_malloc(void *data);
	void link_node_free(p_link_node p);

	link_list *link_list_create();
	int link_list_destory(link_list *l);
	void link_list_append(link_list *l, p_link_node);
	void link_list_order_append(link_list *l, p_link_node);
	void link_list_push(link_list *l, p_link_node p);
	p_link_node link_list_remove(link_list *l, p_link_node node);
	p_link_node link_list_first(link_list *l);
	p_link_node link_list_tail(link_list *l);
	p_link_node link_list_pop_first(link_list *l);
	p_link_node link_list_pop_tail(link_list *l);
	p_link_node link_list_get_next(link_list *l, p_link_node p);
	int link_list_is_empty(link_list *l);

#ifdef __cplusplus
}
#endif
#endif   /* ----- #ifndef _LINK_LIST_H_INC  ----- */

