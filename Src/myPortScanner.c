#include <stdio.h>
#include <sys/socket.h> // socket APIs
#include <netdb.h>      // gethostbyname
#include <string.h>
#include <arpa/inet.h> // inet_ntoa
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/fcntl.h>

#include "arg_parse.h"

struct thread_options {
	char host[INET_ADDRSTRLEN]; //inet_addrstrlen = 16
	int port;
	pthread_t thread_id;
    int timeout;                // timeout pentru fiecare port
    int threads;                // numar de thread-uri
    int start;             // port inceput range
    int end;               // port sfarsit range
    int verbose;                // verbose
};
int scanner_error(const char *s, int sock);

void *thread_routine(void *thread_args)
{
    struct thread_options *args = (struct thread_options *)thread_args;
    int ports[300];
    for (int i = 0; i < args->end - args->start + 1; i++)
    {
        ports[i] = args->start + i;
    }

    for (int i = 0; i < args->end - args->start + 1; i++)
    {
        int port = ports[i];

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        bzero((char *)&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(args->host);

        struct timeval tv;
        tv.tv_sec = args->timeout;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&args->timeout, sizeof(tv));

        int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret >= 0)
        {
            if (args->verbose == 1)
            {
                struct servent *s = getservbyport(htons(port), "tcp");
                if (s)
                    printf("PORT: %d\tSTARE: OPEN\t SERVICE:%s\t PROTOCOL:%s\t\n", port, s->s_name, s->s_proto);
            }
            else
            {
                printf("PORT: %d\tSTARE: OPEN \n", port);
            }
        }

        close(sockfd);
    }
}

void create_thread(struct arguments user_args)
{
    int thread_id;
    pthread_t threads[user_args.threads];
    struct thread_options opt[user_args.threads];

    // Creare thread-uri
    for (thread_id = 0; thread_id < user_args.threads; thread_id++)
    {
        opt[thread_id].thread_id = thread_id;
        opt[thread_id].start = user_args.start_port + 1 + (user_args.end_port - user_args.start_port) / user_args.threads * thread_id;
        opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id + 1);
        strcpy(opt[thread_id].host, user_args.host);
        opt[thread_id].timeout = user_args.timeout;
        opt[thread_id].verbose = user_args.verbose;

        if (pthread_create(&threads[thread_id], NULL, thread_routine, &opt[thread_id]))
        {
            printf("Eroare creare thread\n");
            exit(-1);
        }
    }

    printf("--> Created %d threads.\n", user_args.threads);

    for (thread_id = 0; thread_id < user_args.threads; thread_id++)
    {
        pthread_join(threads[thread_id], NULL);
    }
}

int main(int argc, char **argv)
{
    struct arguments user_args;
    struct hostent *target;
    int rc, fd;
    ///////////////////////////
    user_args = parse_args(argc, argv);

    if (strlen(user_args.host) == 0)
    {
        printf("Introduceti hostname/ip.\n");
        return 0;
    }

    // Resolve hostname
    target = gethostbyname(user_args.host); // transformare nume de domeniu in adresa ip

    bzero(user_args.host, sizeof(user_args.host)); // face user_args->host 0

    strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
    printf("Scanning %s\n", user_args.host);
    create_thread(user_args);

    return 0;
}

int scanner_error(const char *s, int sock)
{
#ifdef DEBUGING
    perror(s);
#endif
    if (sock)
        close(sock);
    return 0;
}