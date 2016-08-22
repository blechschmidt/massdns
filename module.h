#ifndef MASSDNS_MODULE_H
#define MASSDNS_MODULE_H

#include <stdbool.h>
#include <dlfcn.h>

#include <ldns/packet.h>
#include "massdns.h"

void module_init(massdns_module_t *module)
{
    bzero(module, sizeof(*module));
}

bool module_load(massdns_module_t *module, char *filename)
{
    void *handle = dlopen(filename, RTLD_NOW);
    if(!handle)
    {
        return false;
    }
    module->handle_response = dlsym(handle, "massdns_handle_response");
    return true;
}

#endif //MASSDNS_MODULE_H
