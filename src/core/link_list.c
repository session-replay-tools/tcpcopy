#include <xcopy.h>

p_link_node link_node_malloc(void *data)
{
	p_link_node p;

	p = (p_link_node)malloc(sizeof(link_node));
	if(NULL == p){
		return NULL;
	}
	p->data = data;
	p->next = NULL;
	p->prev = NULL;

	return p;
}

void link_node_free(p_link_node p){
	free(p);
}

link_list *link_list_create(){
	link_list *l = (link_list *)malloc(sizeof(link_list));
	if(NULL == l){
		perror("malloc");
		return NULL;
	}
	l->size      = 0;
	l->head.next = &(l->head);
	l->head.prev = &(l->head);
	return l;
}

static int link_list_clear(link_list *l)
{
	p_link_node p ,next;
	int count;

	p = l->head.next;
	count = 0;
	while(p != &(l->head)){
		next = p->next;
		if(p->data != NULL)
		{
			free(p->data);
		}
		count++;
		link_node_free(p);
		p = next;
	}

	return count;

}

int link_list_destory(link_list *l)
{
	int count = link_list_clear(l);
	return count;
}

void link_list_append(link_list *l, p_link_node p)
{
	p_link_node node;
	node = l->head.prev;
	node->next       = p;
	p->prev          = node;
	l->head.prev     = p;
	p->next          = &(l->head);
	l->size++;
}

void link_list_push(link_list *l, p_link_node p){
	p_link_node node;
	node = l->head.next;
	node->prev       = p;
	p->next          = node;
	l->head.next     = p;
	p->prev          = &(l->head);
	l->size++;
	return;
}

p_link_node link_list_remove(link_list *l, p_link_node node)
{
	p_link_node next, prev;
	next = node->next;
	prev = node->prev;
	next->prev = prev;
	prev->next = next;
	l->size--;
	return node;
}

p_link_node link_list_first(link_list *l)
{
	if(l->head.next == &(l->head)){
		return NULL;
	}
	return l->head.next;
}

p_link_node link_list_tail(link_list *l)
{
	if(l->head.next == &(l->head)){
		return NULL;
	}
	return l->head.prev;
}

p_link_node link_list_pop_first(link_list *l)
{
	p_link_node first;
	first = link_list_first(l);
	if(! first){
		return first;
	}
	return link_list_remove(l, first);
}

p_link_node link_list_pop_tail(link_list *l){
	p_link_node tail = link_list_tail(l);
	if(! tail){
		return tail;
	}

	return link_list_remove(l, tail);
}

p_link_node link_list_get_next(link_list *l, p_link_node p){
	if(p->next == &(l->head)){
		return NULL;
	}
	return p->next;
} 

int link_list_is_empty(link_list *l){
	if(l->head.next == &(l->head)){
		return 1;
	}
	return 0;
}

