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

void print_banner()
{
    printf("\033[37m                  ___           _     \033[92m __\n"
           "\033[37m  /\\/\\  _   _    / __\\___  _ __| |_  \033[92m / _\\ ___ __ _ _ __  _ __   ___ _ __\n"
           "\033[37m /    \\| | | |  / /_)/ _ \\| '__| __| \033[92m \\ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|\n"
           "\033[37m/ /\\/\\ \\ |_| | / ___/ (_) | |  | |_  \033[92m _\\ \\ (_| (_| | | | | | | |  __/ |\n"
           "\033[37m\\/    \\/\\__, | \\/    \\___/|_|  \\__| \033[92m  \\__/\\___\\__,_|_| |_|_| |_|\\___|_|\n"
           "\033[37m        |____/\n\n\n");
}

struct thread_options
{
    char host[INET_ADDRSTRLEN]; // inet_addrstrlen = 16
    int port;
    pthread_t thread_id;
    int timeout;   // timeout pentru fiecare port
    int threads;   // numar de thread-uri
    int start;     // port inceput range
    int end;       // port sfarsit range
    int verbose;   // verbose
    int tcp_scan;  // optiune pentru scanare TCP connect
    int syn_scan;  // opțiune pentru scanare SYN
    int udp_scan;  // opțiune pentru scanare UDP
    int null_scan; // opțiune pentru scanare NULL
    int fin_scan;  // opțiune pentru scanare FIN
    int xmas_scan; // opțiune pentru scanare XMAS
};
int scanner_error(const char *s, int sock);

void *thread_routine(void *thread_args)
{
    struct thread_options *args = (struct thread_options *)thread_args;
    int *ports = malloc((args->end - args->start + 1) * sizeof(int));

    for (int i = 0; i < args->end - args->start + 1; i++)
    {
        ports[i] = args->start + i;
    }

    for (int i = 0; i < args->end - args->start + 1; i++)
    {
        int port = ports[i];

        // verific tipul scanarii
        if (args->tcp_scan)
        {

            int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // tratez erori
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
                    struct servent *s = getservbyport(htons(port), "udp");
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
        else if (args->udp_scan)
        {
            int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

            struct sockaddr_in addr;
            bzero((char *)&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(args->host);

            struct timeval tv;
            tv.tv_sec = args->timeout;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&args->timeout, sizeof(tv));

            // int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            int ret = sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&addr, sizeof(addr));

            if (ret >= 0)
            {
                if (args->verbose == 1)
                {
                    struct servent *s = getservbyport(htons(port), "udp");
                    if (s)
                        printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
                }
                else
                {
                    printf("PORT: %d\tSTARE: OPEN \n", port);
                }
            }

            close(sockfd);
        }
        else
        {
            printf("Tip de scanare necunoscut.\n");
            exit(-1);
        }
    }
    free(ports);
    return NULL;
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
        if (thread_id == user_args.threads - 1)  //ultimul thread ia si porturile ramase
        {
            opt[thread_id].start = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * thread_id;
            opt[thread_id].end = user_args.end_port;
        }
        else
        {
            opt[thread_id].start = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * thread_id;
            opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id + 1);
        }
        strcpy(opt[thread_id].host, user_args.host);
        opt[thread_id].timeout = user_args.timeout;
        opt[thread_id].verbose = user_args.verbose;
        opt[thread_id].tcp_scan = user_args.tcp_scan;
        opt[thread_id].syn_scan = user_args.syn_scan;
        opt[thread_id].udp_scan = user_args.udp_scan;
        opt[thread_id].null_scan = user_args.null_scan;
        opt[thread_id].fin_scan = user_args.fin_scan;
        opt[thread_id].xmas_scan = user_args.xmas_scan;

        if (pthread_create(&threads[thread_id], NULL, thread_routine, &opt[thread_id]))
        {
            printf("Eroare creare thread\n");
            exit(-1);
        }
    }

    for (thread_id = 0; thread_id < user_args.threads; thread_id++)
    {
        pthread_join(threads[thread_id], NULL);
    }
}

int main(int argc, char **argv)
{
    print_banner();
    struct arguments user_args;
    struct hostent *target;

    user_args = parse_args(argc, argv);

    if (strlen(user_args.host) == 0)
    {
        printf("Introduceti hostname/ip.\n");
        return 0;
    }
    
    target = gethostbyname(user_args.host); // transformare nume de domeniu in adresa ip
    int retry_count = 0;
    while (target == NULL && h_errno == TRY_AGAIN && retry_count < 3)
    {
        sleep(5);
        target = gethostbyname(user_args.host);
        retry_count++;
    }

    if (target == NULL)
    {
        perror("gethostbyname");
        exit(-1);
    }

    bzero(user_args.host, sizeof(user_args.host)); // face user_args->host 0

    strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0]))); 

    if(user_args.udp_scan){
        printf("UDP scan\n");
    }else{
        printf("TCP scan\n");
    }
    printf("Scanning %s\n\n", user_args.host);
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