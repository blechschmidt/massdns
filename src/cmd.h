#include "massdns.h"

#ifndef MASSDNS_CMD_H
#define MASSDNS_CMD_H

void expect_arg(int i)
{
    if (i + 1 >= context.cmd_args.argc)
    {
        fprintf(stderr, "Missing argument value for %s.\n", context.cmd_args.argv[i]);
        context.cmd_args.help_function();
        exit(1);
    }
}

unsigned long long expect_arg_nonneg(int i, unsigned long long min, unsigned long long max)
{
    expect_arg(i);
    char *endptr;
    unsigned long long result = strtoull(context.cmd_args.argv[i + 1], &endptr, 10);
    if(*endptr != 0 || result < min || result > max)
    {
        fprintf(stderr, "The argument %s requires a value between %llu and %llu.\n",
                context.cmd_args.argv[i], min, max);
        exit(1);
    }
    return result;
}

#endif
