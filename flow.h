#ifndef MASSDNS_FLOW_H
#define MASSDNS_FLOW_H

#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// times is the number of resulting processes, i.e. if times is two, the process will fork once
size_t split_process(size_t times)
{
    for (size_t i = 0; i < times - 1; i++)
    {
        pid_t child = fork();
        switch (child)
        {
            case -1:
            {
                perror("Failed to fork");
                exit(EXIT_FAILURE);
            }
            case 0:
            {
                prctl(PR_SET_PDEATHSIG, SIGHUP);
                return i + 1;
            }
            default:
                break;
        }
    }
    return 0;
}

#endif
