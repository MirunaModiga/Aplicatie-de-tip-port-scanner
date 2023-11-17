#include <argp.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <netdb.h>
///////////////////

struct arguments
{
    char host[INET_ADDRSTRLEN]; // hostname sau IP
    int timeout;                // timeout pentru fiecare port
    int threads;                // numar de thread-uri
    int start_port;             // port inceput range
    int end_port;               // port sfarsit range
    int verbose;                // verbose
    int menu;
};

struct argp_option options[] = {
    {"host", 'h', "HOST", 0, "Target host to scan"},
    {"timeout", 't', "SECONDS", 0, "Speed of scanning/seconds of timeout."},
    {"port", 'p', "PORT", 0, "Port range to scan"},
    {"threads", 'T', "THREADS", 0, "Number of threads to use for the scan"},
    {"verbose", 'v', "VERBOSE", 0, "Verbose mode"},
    {0}};

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    switch (key)
    {
    case 'h':
        strncpy(arguments->host, arg, (size_t)INET_ADDRSTRLEN);
        break;
    case 't':
        arguments->timeout = atoi(arg);
        break;
    case 'T':
        arguments->threads = atoi(arg);
        break;
    case 'p':;
        char range[20];
        strncpy(range, arg, 20);
        char *dash = strchr(range, '-');
        if (dash == NULL)
        {
            arguments->start_port = arguments->end_port = atoi(range);
        }
        else
        {
            *dash = '\0';
            arguments->start_port = atoi(range);
            arguments->end_port = atoi(dash + 1);
        }
        break;
    case 'v':
        arguments->verbose = 1;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp argp = {options, parse_opt};

struct arguments parse_args(int argc, char *argv[])
{
    static struct arguments arguments;
    strcpy(arguments.host, "");
    arguments.timeout = 5;
    arguments.threads = 5;
    arguments.start_port = 1;
    arguments.end_port = 65535;
    arguments.verbose = 0;

    int i = argp_parse(&argp, argc, argv, 0, 0, &arguments);
    return arguments;
}