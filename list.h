#ifndef INC_LIST
#define INC_LIST

#include "buffers.h"
#include "security.h"
#include <stdbool.h>

#define single_list_foreach(list, element) for (single_list_element_t *(element) = (list).first; (element) != NULL; (element) = (element)->next)
#define single_list_ref_foreach(list, element) for (single_list_element_t *(element) = (list)->first; (element) != NULL; (element) = (element)->next)
#define single_list_foreach_free(list, element) for (single_list_element_t *(element) = (list).first; (element) != NULL; (element) = single_list_free_and_next(element))
#define single_list_ref_foreach_free(list, element) for (single_list_element_t *(element) = (list)->first; (element) != NULL; (element) = single_list_free_and_next(element))

#define double_list_foreach_free(list, element) for (double_list_element_t *(element) = (list).first; (element) != NULL; (element) = double_list_free_and_next(element))

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

bool single_list_iterate(single_list_t *list, bool (*f)(void *, void *), void *param)
{
    single_list_element_t* element = list->first;
    while (element != NULL)
    {
        single_list_element_t *next = element->next;
        if(!f(element->data, param))
        {
            return false;
        }
        element = next;
    }
    return true;
}

bool single_list_iterate_free(single_list_t *list, bool (*f)(void *, void *), void *param)
{
    single_list_element_t* element = list->first;
    while (element != NULL)
    {
        single_list_element_t *next = element->next;
        if(!f(element->data, param))
        {
            return false;
        }
        free(element);
        list->first = next;
        list->count--;
        element = next;
    }
    list->last = NULL;
    return true;
}

bool single_list_element_set_array_element(void *element, void *param)
{
    buffer_t *buffer = param;
    void **data = buffer->data;
    data[buffer->len++] = element;
    return true;
}

buffer_t single_list_to_array(single_list_t *list)
{
    buffer_t buf;
    buf.len = 0;
    buf.data = safe_malloc(sizeof(buf.data) * list->count);
    single_list_iterate(list, single_list_element_set_array_element, &buf);
    return buf;
}

buffer_t single_list_to_array_copy(single_list_t *list, size_t element_size)
{
    buffer_t buf;
    buf.len = list->count;
    buf.data = safe_malloc(element_size * list->count);
    size_t i = 0;
    single_list_ref_foreach(list, element)
    {
        memcpy(((uint8_t*)buf.data) + (i++) * element_size, element->data, element_size);
    }
    return buf;
}

single_list_t *single_list_new()
{
    single_list_t *list = safe_calloc(sizeof(*list));
    return list;
}

void single_list_init(single_list_t *list)
{
    bzero(list, sizeof(*list));
}

void single_list_cat(single_list_t* left, single_list_t* right)
{
    if(left->last != NULL)
    {
        left->last->next = right->first;
    }
    else
    {
        left->first = right->first;
        left->last = right->last;
    }
    left->count += right->count;
    left->last = right->last;
}

void single_list_clear(single_list_t *list)
{
    single_list_element_t *element = list->first;
    while (element != NULL)
    {
        single_list_element_t *next = element->next;
        free(element);
        element = next;
    }
    single_list_init(list);
}

void single_list_free(single_list_t *list)
{
    if(list != NULL)
    {
        single_list_clear(list);
    }
    free(list);
}

void single_list_free_elements(single_list_t *list)
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
}

void single_list_free_with_elements(single_list_t *list)
{
    single_list_free_elements(list);
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

single_list_element_t *single_list_push_back(single_list_t *list, void *data)
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
    return new_element;
}

/**
 * Pop the first element from a list and push it to the back.
 *
 * @param list The list to be wrapped.
 */
void single_list_wrap_first(single_list_t *list)
{
    if(list->first == NULL)
    {
        return;
    }
    list->last->next = list->first;
    list->last = list->first;
    list->first = list->first->next;
    list->last->next = NULL;
}

double_list_t* double_list_new()
{
    double_list_t *list = safe_calloc(sizeof(*list));
    return list;
}

void double_list_init(double_list_t *list)
{
    bzero(list, sizeof(*list));
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

double_list_element_t *double_list_push_back(double_list_t *list, void *data)
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
    return new_element;
}

void double_list_clear(double_list_t *list)
{
    double_list_element_t *element = list->first;
    while (element != NULL)
    {
        double_list_element_t *next = element->next;
        free(element);
        element = next;
    }
    double_list_init(list);
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

double_list_element_t* double_list_free_and_next(double_list_element_t *element)
{
    double_list_element_t *next = element->next;
    free(element);
    return next;
}

single_list_element_t* single_list_free_and_next(single_list_element_t *element)
{
    single_list_element_t *next = element->next;
    free(element);
    return next;
}

void single_list_remove(single_list_t* list, void *value)
{
    single_list_element_t *last = NULL;
    single_list_element_t *element = list->first;
    while (element != NULL)
    {
        if(element->data == value)
        {
            if(last == NULL)
            {
                list->first = list->first->next;
            }
            else
            {
                last->next = element->next;
            }
            if(element == list->last)
            {
                list->last = last;
            }
            list->count--;
            element = single_list_free_and_next(element);
        }
        else
        {
            last = element;
            element = element->next;
        }
    }
}

#endif
