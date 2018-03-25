#ifndef MASSDNS_FLOW_H
#define MASSDNS_FLOW_H

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

static void kill_process_group(int sig)
{
    static int received_termination = 0;

    if(received_termination)
    {
        return;
    }
    received_termination = 1;
    kill(0, sig);
}

static void handle_termination()
{
    signal(SIGINT, kill_process_group);
    signal(SIGTERM, kill_process_group);
}

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
                handle_termination();
                return i + 1;
            }
            default:
                break;
        }
    }
    handle_termination();
    return 0;
}

#endif
