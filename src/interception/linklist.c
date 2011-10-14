#include <stdlib.h>
#include <stdio.h>

#include "linklist.h"

lnodeptr lnode_malloc(void *data){
	lnodeptr p;
	if(NULL == (p = (lnodeptr)malloc(sizeof(struct linknode)))){
		return NULL;
	}
	p->data = data;
	p->next = NULL;
	p->prev = NULL;
	return p;
}

void lnode_free(lnodeptr p){
	free(p);
}

linklist * linklist_create(){
	linklist *l= (linklist *)malloc(sizeof(struct linklist ));
	if(! l){
		perror("malloc");
		return NULL;
	}
	l->head.next = & l->head;
	l->head.prev = & l->head;
	return l;
}

static int linklist_clear(linklist *l){
	lnodeptr p = l->head.next;
	lnodeptr pnext;
	int count=0;
	while(p !=& l->head){
		pnext = p->next;
		if(p->data!=NULL)
		{
			free(p->data);
		}
		count++;
		lnode_free(p);
		p = pnext;
	}
	return count;
}

int linklist_destory(linklist *l){
	int count=linklist_clear(l);
	free(l);
	return count;
}

void linklist_append(linklist *l,lnodeptr p){
	lnodeptr node =l->head.prev;
	node->next = p;
	p->prev = node;
	l->head.prev = p;
	p->next =& l->head;
}

void linklist_push(linklist *l,lnodeptr p){
	lnodeptr node =l->head.next;
	node->prev = p;
	p->next = node;
	l->head.next = p;
	p->prev = & l->head;
	return;
}

lnodeptr linklist_remove(lnodeptr node){
	lnodeptr pnext = node->next;
	lnodeptr pprev = node->prev;
	pnext->prev = pprev;
	pprev->next = pnext;
	return node;
}

lnodeptr linklist_first(linklist *l){
	if(l->head.next ==& l->head){
		return NULL;
	}
	return l->head.next;
}
lnodeptr linklist_tail(linklist *l){
	if(l->head.next ==& l->head){
		return NULL;
	}
	return l->head.prev;
}

lnodeptr linklist_pop_first(linklist *l){
	lnodeptr first = linklist_first(l);
	if(! first){
		return first;
	}
	return linklist_remove(first);
}

lnodeptr linklist_pop_tail(linklist *l){
	lnodeptr tail = linklist_tail(l);
	if(! tail){
		return tail;
	}
	return linklist_remove(tail);
}

lnodeptr linklist_get_next(linklist *l,lnodeptr p){
	if(p->next == & l->head){
		return NULL;
	}
	return p->next;
} 

int linklist_is_empty(linklist *l){
	if(l->head.next == & l->head){
		return 1;
	}
	return 0;
}

