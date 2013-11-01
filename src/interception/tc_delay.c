
#include <xcopy.h>
#include <intercept.h>

static uint64_t     msg_item_cnt, msg_item_free_cnt, msg_item_destr_cnt,
                    msg_ls_cnt, msg_ls_free_cnt, msg_ls_destr_cnt, 
                    msg_delay_sent_cnt;

static hash_table  *table;

static struct msg_server_s *
copy_message(struct msg_server_s *msg)
{
    struct msg_server_s *cmsg;

    cmsg = (struct msg_server_s *) malloc(sizeof(struct msg_server_s));
    if (cmsg == NULL) {
        tc_log_info(LOG_ERR, errno, "malloc error");
        return NULL;
    }
    memcpy(cmsg, msg, sizeof(struct msg_server_s));

    return cmsg;
}

void
delay_table_delete_obsolete(time_t cur_time)
{
    int          i, count = 0;
    hash_node   *hn1, *hn2;
    link_list   *msg_list, *l;
    p_link_node  ln, tail;

    tc_log_info(LOG_NOTICE, 0, "delay total:%u", table->total);

    for (i = 0; i < table->size; i++) {
        l  = table->lists[i];
        while (true) {

            ln = link_list_tail(l);
            if (ln == NULL) {
                break;
            }   

            hn1 = (hash_node *) ln->data;
            if ( (hn1->access_time + table->timeout) < cur_time) {
                count++;
                table->total--;
                tail = link_list_pop_tail(l);
                hn2  = (hash_node *) tail->data;
                if (hn2 != NULL) {   
                    if (hn2->data != NULL) {
                        msg_list = (link_list *) hn2->data;
                        msg_item_destr_cnt += link_list_clear(msg_list);
                        free(msg_list);     
                        hn2->data = NULL;
                        msg_ls_destr_cnt++;
                    }
                    free(hn2);
                }   
                tail->data = NULL;
                free(tail);
            } else {
                break;
            }   
        } 
    }

    tc_log_info(LOG_NOTICE, 0, "delay delete obsolete :%d", count);
}


/* init delay table */
void
delay_table_init(size_t size)
{
    table = hash_create(size);
    hash_set_timeout(table, 30);
    strcpy(table->name, "delay-table");
    tc_log_info(LOG_NOTICE, 0, "create %s,size:%u", table->name, table->size);
    msg_item_cnt       = 0;
    msg_item_free_cnt  = 0;
    msg_item_destr_cnt = 0;
    msg_ls_cnt         = 0;
    msg_ls_destr_cnt   = 0;
    msg_delay_sent_cnt = 0;
}

/* add message to delay table */
void
delay_table_add(uint64_t key, struct msg_server_s *msg)
{
    link_list           *msg_list;
    p_link_node          ln;
    struct msg_server_s *cmsg;

    msg_list = (link_list *) hash_find(table, key);
    if (msg_list == NULL) {
        msg_ls_cnt++;
        msg_list = link_list_create();
        hash_add(table, key, msg_list);
    }

    cmsg = copy_message(msg);
    if (cmsg != NULL) {
        ln   = link_node_malloc((void *) cmsg);
        link_list_append(msg_list, ln);

        msg_item_cnt++;
    }

    return;
}


/* send delayed message according to the key */
void
delay_table_send(uint64_t key, int fd)
{
    link_list           *msg_list;
    p_link_node          first;
    msg_server_t        *msg ;

    msg_list = (link_list *) hash_find(table, key);
    if (msg_list == NULL) {
        return; 
    }

    while (!link_list_is_empty(msg_list)) {
        first = link_list_pop_first(msg_list);
        msg = (first->data);

#if (INTERCEPT_COMBINED)
        buffer_and_send(fd, msg);
#else
        if (tc_socket_send(fd, (char *) msg, MSG_SERVER_SIZE) == TC_ERROR) {
            tc_intercept_release_tunnel(fd, NULL);
        }
#endif
        msg_delay_sent_cnt++;

        msg_item_free_cnt++;
        link_node_internal_free(first);
        free(first);
    }

}

/* delete delay table item according to the key */
void
delay_table_del(uint64_t key)
{
    link_list    *msg_list;
    p_link_node   first;

    msg_list = (link_list *) hash_find(table, key);
    if (msg_list == NULL) {
        return; 
    }

    while (!link_list_is_empty(msg_list)) {
        first = link_list_pop_first(msg_list);
        msg_item_free_cnt++;
        link_node_internal_free(first);
        free(first);
    }

    hash_del(table, key);
    free(msg_list);
    msg_ls_free_cnt++;
}

/* destroy delay table */
void
delay_table_destroy()
{
    uint32_t     i;
    link_list   *msg_list, *list;
    hash_node   *hn;
    p_link_node  ln;

    if (table != NULL) {

        tc_log_info(LOG_NOTICE, 0, "destroy delay table,total:%u",
                table->total);

        for (i = 0; i < table->size; i++) {
            list = table->lists[i];
            ln   = link_list_first(list);
            while (ln) {
                hn = (hash_node *) ln->data;
                if (hn->data != NULL) {
                    msg_list = (link_list *) hn->data;
                    msg_item_destr_cnt += link_list_clear(msg_list);
                    free(msg_list);
                    msg_ls_destr_cnt++;
                }   
                hn->data = NULL;
                ln = link_list_get_next(list, ln);
            }
        }

        tc_log_info(LOG_NOTICE, 0, "destroy items:%llu,free:%llu,total:%llu",
                msg_item_destr_cnt, msg_item_free_cnt, msg_item_cnt);
        tc_log_info(LOG_NOTICE, 0, "create msg list:%llu,free:%llu,destr:%llu",
                msg_ls_cnt, msg_ls_free_cnt, msg_ls_destr_cnt);
        tc_log_info(LOG_NOTICE, 0, "delay actual sent:%llu", 
                msg_delay_sent_cnt);


        hash_destroy(table);
        free(table);
        table = NULL;
    }
}

