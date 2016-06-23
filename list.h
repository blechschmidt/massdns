#ifndef INC_LIST
#define INC_LIST

#include "buffers.h"
#include "security.h"

typedef struct single_list
{
    void *data;
    struct single_list *next;
} single_list_t;

typedef struct double_list
{
    void *data;
    struct double_list *previous;
    struct double_list *next;
} double_list_t;

void single_list_iterate(single_list_t *list, void (*f)(single_list_t *, size_t, void *), void *param)
{
    size_t counter = 0;
    while (list != NULL)
    {
        single_list_t *next = list->next;
        f(list, counter++, param);
        list = next;
    }
}

size_t _single_list_get_size(single_list_t *list, size_t size)
{
    if (list == NULL)
    {
        return size;
    }
    else
    {
        return _single_list_get_size(list->next, size + 1);
    }
}

size_t single_list_get_size(single_list_t *list)
{
    return _single_list_get_size(list, 0);
}

void single_list_set_array_element(single_list_t *list, size_t index, void *param)
{
    ((void **) param)[index] = list->data;
}

buffer_t single_list_to_array(single_list_t *list)
{
    buffer_t buf;
    buf.len = single_list_get_size(list);
    buf.data = safe_malloc(sizeof(buf.data) * buf.len);
    single_list_iterate(list, single_list_set_array_element, buf.data);
    return buf;
}

void single_list_delete_element(single_list_t *list, size_t index, void *param)
{
    free(list->data);
    free(list);
}

void single_list_free(single_list_t *list)
{
    single_list_iterate(list, single_list_delete_element, NULL);
}

void single_list_append(single_list_t *list, void* data)
{
    while(list->next != NULL)
    {
        list = list->next;
    }
    list->next = safe_malloc(sizeof(single_list_t));
    list->next->next = NULL;
    list->next->data = data;
}

void single_list_push_front(single_list_t **list, void* data)
{
    single_list_t* new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = *list;
    *list = new_element;
}

void* single_list_pop_front(single_list_t **list)
{
    single_list_t* front = *list;
    void* result = front->data;
    *list = front->next;
    free(front);
    return result;
}

#endif
