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
    int verbose;                // serviciu
    int tcp_scan;               // optiune pentru scanare TCP connect
    int syn_scan;               // opțiune pentru scanare SYN
    int udp_scan;               // opțiune pentru scanare UDP
    int null_scan;              // opțiune pentru scanare NULL
    int fin_scan;               // opțiune pentru scanare FIN
    int xmas_scan;              // opțiune pentru scanare XMAS
    int ack_scan;               // optiune pentru scanare ACK
    int window_scan;            // optiune pentru scanare TCP window
    char custom[20];            // optiunea pt flaguri scanare custom
};

struct argp_option options[] = {
    {"host", 'h', "HOST", 0, "Target host to scan"},
    {"timeout", 't', "SECONDS", 0, "Speed of scanning/seconds of timeout."},
    {"port", 'p', "PORT NUMBER RANGE", 0, "Port range to scan"},
    {"threads", 'T', "THREADS NUMBER", 0, "Number of threads to use for the scan"},
    {"verbose", 'v', "VERBOSE 1/0", 0, "Verbose mode"},
    {"scan type", 's', "SCAN_TYPE", 0, "TCP/UDP/SYN/NULL/FIN/XMAS"},
    {"custom scan", 'c', "Customize flags", 0, "SYN/ACK/FIN/RST/PSH/URG"},
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
    case 'c':
        strcpy(arguments->custom, arg);
        break;
    case 's':
        if (arg != NULL)
        {
            if (arg[0] == 'T')
            {
                arguments->tcp_scan = 1;
            }
            else if (arg[0] == 'S')
            {
                arguments->syn_scan = 1;
            }
            else if (arg[0] == 'U')
            {
                arguments->udp_scan = 1;
            }
            else if (arg[0] == 'N')
            {
                arguments->null_scan = 1;
            }
            else if (arg[0] == 'F')
            {
                arguments->fin_scan = 1;
            }
            else if (arg[0] == 'X')
            {
                arguments->xmas_scan = 1;
            }
            else if (arg[0] == 'A')
            {
                arguments->ack_scan = 1;
            }
            else if (arg[0] == 'W')
            {
                arguments->window_scan = 1;
            }
        }
        break;
    case 'H':
        argp_state_help(state, stdout, ARGP_HELP_LONG | ARGP_HELP_PRE_DOC);
        exit(0);
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp argp = {options, parse_opt};
//https://www.gnu.org/software/libc/manual/html_node/Argp-Example-3.html

struct arguments parse_args(int argc, char *argv[])
{
    struct arguments arguments;
    strcpy(arguments.host, "");
    arguments.timeout = 5;
    arguments.threads = 5;
    arguments.start_port = 1;
    arguments.end_port = 65535;
    arguments.verbose = 0;
    arguments.tcp_scan = 0;
    arguments.syn_scan = 0;
    arguments.udp_scan = 0;
    arguments.null_scan = 0;
    arguments.fin_scan = 0;
    arguments.xmas_scan = 0;
    arguments.ack_scan = 0;
    arguments.window_scan = 0;
    strcpy(arguments.custom, "");

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    return arguments;
}
