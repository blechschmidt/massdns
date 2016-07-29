#ifndef INC_LIST
#define INC_LIST

#include "buffers.h"
#include "security.h"

typedef struct single_list_element
{
    void *data;
    struct single_list_element *next;
} single_list_element_t;

typedef struct
{
    size_t count;
    single_list_element_t* first;
    single_list_element_t* last;
} single_list_t;

typedef struct double_list_element
{
    void *data;
    struct double_list_element *previous;
    struct double_list_element *next;
} double_list_element_t;

typedef struct
{
    size_t element_count;
    double_list_element_t* first;
    double_list_element_t* last;
} double_list_t;

void single_list_element_iterate(single_list_element_t *list, void (*f)(single_list_element_t *, size_t, void *),
                                 void *param)
{
    size_t counter = 0;
    while (list != NULL)
    {
        single_list_element_t *next = list->next;
        f(list, counter++, param);
        list = next;
    }
}

size_t _single_list_element_get_size(single_list_element_t *list, size_t size)
{
    if (list == NULL)
    {
        return size;
    }
    else
    {
        return _single_list_element_get_size(list->next, size + 1);
    }
}

size_t single_list_element_get_size(single_list_element_t *list)
{
    return _single_list_element_get_size(list, 0);
}

void single_list_element_set_array_element(single_list_element_t *list, size_t index, void *param)
{
    ((void **) param)[index] = list->data;
}

buffer_t single_list_element_to_array(single_list_element_t *list)
{
    buffer_t buf;
    buf.len = single_list_element_get_size(list);
    buf.data = safe_malloc(sizeof(buf.data) * buf.len);
    single_list_element_iterate(list, single_list_element_set_array_element, buf.data);
    return buf;
}

void* single_list_get_front(single_list_t* list)
{
    return list->first->data;
}

single_list_t* single_list_new()
{
    single_list_t* list = safe_calloc(sizeof(*list));
    return list;
}

void single_list_free(single_list_t* list_holder)
{
    single_list_element_t* list = list_holder->first;
    while (list != NULL)
    {
        single_list_element_t *next = list->next;
        free(list);
        list = next;
    }
}

void single_list_push_front(single_list_t *list, void* data)
{
    single_list_element_t* new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = list->first;
    list->first = new_element;
    if(list->last == NULL)
    {
        list->last = new_element;
    }
    list->count++;
}

void single_list_push_back(single_list_t* list, void* data)
{
    single_list_element_t* new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = NULL;
    list->count++;
    if(list->last)
    {
        list->last->next = new_element;
    }
    else
    {
        list->first = new_element;
        list->last = new_element;
    }
}

/*void single_list_delete_element(single_list_element_t *list, size_t index, void *param)
{
    free(list->data);
    free(list);
}

void single_list_free(single_list_element_t *list)
{
    single_list_element_iterate(list, single_list_delete_element, NULL);
}

void single_list_append(single_list_element_t *list, void* data)
{
    while(list->next != NULL)
    {
        list = list->next;
    }
    list->next = safe_malloc(sizeof(single_list_element_t));
    list->next->next = NULL;
    list->next->data = data;
}

void* single_list_pop_front(single_list_element_t **list)
{
    single_list_element_t* front = *list;
    void* result = front->data;
    *list = front->next;
    free(front);
    return result;
}

void* single_list_get_front(single_list_element_t *list)
{
    if(list)
    {
        return list->data;
    }
    return NULL;
}

void double_list_push_front(double_list_t *list_holder, void* data)
{
    double_list_element_t* element = safe_malloc(sizeof(*element));
}

void double_list_push_back(double_list_t *list_holder, void* data)
{
    double_list_element_t* element = safe_malloc(sizeof(*element));
    element->data = data;
    element->next = NULL;
    list_holder->last = element;
}

void double_list_iterate(double_list_t *list_holder, void (*f)(double_list_element_t *, size_t, void *), void *param)
{
    double_list_element_t* list = list_holder->first;
    size_t counter = 0;
    while (list != NULL)
    {
        double_list_element_t *next = list->next;
        f(list, counter++, param);
        list = next;
    }
}
 */

#endif
