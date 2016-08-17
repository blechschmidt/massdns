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
    single_list_element_t *first;
    single_list_element_t *last;
} single_list_t;

typedef struct double_list_element
{
    void *data;
    struct double_list_element *previous;
    struct double_list_element *next;
} double_list_element_t;

typedef struct
{
    size_t count;
    double_list_element_t *first;
    double_list_element_t *last;
} double_list_t;

size_t single_list_count(single_list_t* list)
{
    return list->count;
}

void single_list_iterate(single_list_t *list, void (*f)(single_list_element_t *, size_t, void *), void *param)
{
    if(list == NULL)
    {
        return;
    }
    single_list_element_t* element = list->first;
    size_t counter = 0;
    while (element != NULL)
    {
        single_list_element_t *next = element->next;
        f(element, counter++, param);
        element = next;
    }
}

void single_list_element_set_array_element(single_list_element_t *list, size_t index, void *param)
{
    ((void **) param)[index] = list->data;
}

buffer_t single_list_to_array(single_list_t *list)
{
    buffer_t buf;
    buf.len = list->count;
    buf.data = safe_malloc(sizeof(buf.data) * buf.len);
    single_list_iterate(list, single_list_element_set_array_element, buf.data);
    return buf;
}

single_list_t *single_list_new()
{
    single_list_t *list = safe_calloc(sizeof(*list));
    return list;
}

void single_list_cat(single_list_t* left, single_list_t* right)
{
    left->count += right->count;
    left->last = right->last;
    left->last->next = right->first;
    safe_free(&right);
}

void single_list_free(single_list_t *list_holder)
{
    if(list_holder == NULL)
    {
        return;
    }
    single_list_element_t *list = list_holder->first;
    while (list != NULL)
    {
        single_list_element_t *next = list->next;
        free(list);
        list = next;
    }
    free(list_holder);
}

void single_list_free_with_elements(single_list_t *list)
{
    if(list == NULL)
    {
        return;
    }
    single_list_element_t *current = list->first;
    while(current != NULL)
    {
        single_list_element_t *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
    free(list);
}

void single_list_push_front(single_list_t *list, void *data)
{
    single_list_element_t *new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = list->first;
    if (list->last == NULL)
    {
        list->last = new_element;
    }
    list->first = new_element;
    list->count++;
}

void single_list_push_back(single_list_t *list, void *data)
{
    single_list_element_t *new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = NULL;
    list->count++;
    if (list->last)
    {
        list->last->next = new_element;
    }
    else
    {
        list->first = new_element;
    }
    list->last = new_element;
}

double_list_t* double_list_new()
{
    double_list_t *list = safe_calloc(sizeof(*list));
    return list;
}

void double_list_free(double_list_t *list_holder)
{
    double_list_element_t *list = list_holder->first;
    while (list != NULL)
    {
        double_list_element_t *next = list->next;
        free(list);
        list = next;
    }
}

void double_list_push_front(double_list_t *list, void *data)
{
    double_list_element_t *new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = list->first;
    new_element->previous = NULL;
    if (list->last == NULL)
    {
        list->last = new_element;
    }
    list->first = new_element;
    list->count++;
}

void double_list_push_back(double_list_t *list, void *data)
{
    double_list_element_t *new_element = safe_malloc(sizeof(*new_element));
    new_element->data = data;
    new_element->next = NULL;
    new_element->previous = list->last;
    list->count++;
    if (list->last)
    {
        list->last->next = new_element;
    }
    else
    {
        list->first = new_element;
    }
    list->last = new_element;
}

void double_list_iterate(double_list_t *list, void (*f)(double_list_element_t *, size_t, void *), void *param)
{
    double_list_element_t* element = list->first;
    size_t counter = 0;
    while (element != NULL)
    {
        double_list_element_t *next = element->next;
        f(element, counter++, param);
        element = next;
    }
}

#endif
