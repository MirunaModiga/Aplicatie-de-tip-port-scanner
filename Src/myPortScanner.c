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
#include <netinet/tcp.h> // tcp header
#include <netinet/ip.h>  // ip header
#include <inttypes.h>
#include <string.h>
#include "arg_parse.h"
#define __BYTE_ORDER __LITTLE_ENDIAN
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

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
    int timeout;     // timeout pentru fiecare port
    int threads;     // numar de thread-uri
    int start;       // port inceput range
    int end;         // port sfarsit range
    int verbose;     // verbose
    int tcp_scan;    // optiune pentru scanare TCP connect
    int syn_scan;    // opțiune pentru scanare SYN
    int udp_scan;    // opțiune pentru scanare UDP
    int null_scan;   // opțiune pentru scanare NULL
    int fin_scan;    // opțiune pentru scanare FIN
    int xmas_scan;   // opțiune pentru scanare XMAS
    int ack_scan;    // optiune scanare TCP ACK
    int window_scan; // optiune scanare TCP Window
    char custom[20];
};

int get_local_ip(char **source_ip)
{
    const char *google_dns_server = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 0;
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_server);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);

    char buffer[100];
    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    *source_ip = strdup(buffer);

    close(sock);
}

void TCP_scan(struct thread_options *args, int port)
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
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

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

void UDP_scan(struct thread_options *args, int port)
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

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

void CustomScan(struct thread_options *args, int port)
{
    int sockfd;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char packet[4096];
    struct pseudo_header psh;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    char *source_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    get_local_ip(&source_ip);

    ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(args->host);

    ip_header->check = csum((unsigned short *)packet, ip_header->tot_len / 2); // >>1

    tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

    tcp_header->th_sport = htons(rand() % (65535 - 1024) + 1024);
    tcp_header->th_dport = htons((uint16_t)port);

    tcp_header->seq = rand();
    tcp_header->ack_seq = 0;

    tcp_header->res1 = (uint16_t)0;
    tcp_header->doff = (uint16_t)5;

    tcp_header->fin = (uint16_t)1;
    tcp_header->syn = (uint16_t)0;
    tcp_header->rst = (uint16_t)0;
    tcp_header->psh = (uint16_t)0;
    tcp_header->ack = (uint16_t)0;
    tcp_header->urg = (uint16_t)0;

    if (strstr(args->custom, "SYN") != NULL)
    {
        tcp_header->syn = (uint16_t)1;
    }
    if (strstr(args->custom, "FIN") != NULL)
    {
        tcp_header->fin = (uint16_t)1;
    }
    if (strstr(args->custom, "ACK") != NULL)
    {
        tcp_header->ack = (uint16_t)1;
    }
    if (strstr(args->custom, "URG") != NULL)
    {
        tcp_header->urg = (uint16_t)1;
    }
    if (strstr(args->custom, "PSH") != NULL)
    {
        tcp_header->psh = (uint16_t)1;
    }
    if (strstr(args->custom, "RST") != NULL)
    {
        tcp_header->rst = (uint16_t)1;
    }

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
        return;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(args->host);

    psh.source_address = inet_addr(source_ip);
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));

    tcp_header->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

    // Trimitere packet
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        printf("Error: sendto() failed.\n");
        close(sockfd);
        return;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("Error setting SO_RCVTIMEO");
        close(sockfd);
        return;
    }

    // Primire raspuns
    char recv_buf[4096];
    struct sockaddr_in recv_src;
    socklen_t recv_src_len = sizeof(recv_src);

    int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_src, &recv_src_len);

    if (recv_len < 0)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            printf("TIMEOUT \n");
            return;
        }
        else
        {
            perror("Error: recvfrom() failed.");
        }

        close(sockfd);
        return;
    }

    ip_header = (struct iphdr *)recv_buf;
    tcp_header = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));

    fflush(stdout);

    if (tcp_header->rst == 1 && tcp_header->ack == 1)
    {
        if (args->verbose == 1)
        {
            struct servent *s = getservbyport(htons(port), "tcp");
            if (s)
                printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
        }
        else
        {
            printf("PORT: %d\tSTARE: OPEN \n", port);
        }
    }
    else
    {
        printf("PORT: %d\tFILTERED\n", port);
    }

    close(sockfd);
}

void SYN_NULL_FIN_XMAS_scan(struct thread_options *args, int port)
{
    int sockfd;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char packet[4096];
    struct pseudo_header psh;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    char *source_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    get_local_ip(&source_ip);

    ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(args->host);

    ip_header->check = csum((unsigned short *)packet, ip_header->tot_len / 2); // >>1

    tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

    tcp_header->th_sport = htons(rand() % (65535 - 1024) + 1024);
    tcp_header->th_dport = htons((uint16_t)port);

    tcp_header->seq = rand();
    tcp_header->ack_seq = 0;

    tcp_header->res1 = (uint16_t)0;
    tcp_header->doff = (uint16_t)5;

    if (args->fin_scan == 1)
    {
        tcp_header->fin = (uint16_t)1;
        tcp_header->syn = (uint16_t)0;
        tcp_header->rst = (uint16_t)0;
        tcp_header->psh = (uint16_t)0;
        tcp_header->ack = (uint16_t)0;
        tcp_header->urg = (uint16_t)0;
    }
    else if (args->null_scan == 1)
    {
        tcp_header->fin = (uint16_t)0;
        tcp_header->syn = (uint16_t)0;
        tcp_header->rst = (uint16_t)0;
        tcp_header->psh = (uint16_t)0;
        tcp_header->ack = (uint16_t)0;
        tcp_header->urg = (uint16_t)0;
    }
    else if (args->syn_scan == 1)
    {
        tcp_header->fin = (uint16_t)0;
        tcp_header->syn = (uint16_t)1;
        tcp_header->rst = (uint16_t)0;
        tcp_header->psh = (uint16_t)0;
        tcp_header->ack = (uint16_t)0;
        tcp_header->urg = (uint16_t)0;
    }
    else if (args->xmas_scan == 1)
    {
        tcp_header->fin = (uint16_t)1;
        tcp_header->syn = (uint16_t)0;
        tcp_header->rst = (uint16_t)0;
        tcp_header->psh = (uint16_t)1;
        tcp_header->ack = (uint16_t)0;
        tcp_header->urg = (uint16_t)1;
    }
    else if (args->ack_scan == 1 || args->window_scan == 1)
    {
        tcp_header->fin = (uint16_t)0;
        tcp_header->syn = (uint16_t)0;
        tcp_header->rst = (uint16_t)0;
        tcp_header->psh = (uint16_t)0;
        tcp_header->ack = (uint16_t)1;
        tcp_header->urg = (uint16_t)0;
    }

    tcp_header->res2 = (uint16_t)0;
    tcp_header->window = (uint16_t)1;
    tcp_header->check = (uint16_t)0;
    tcp_header->urg_ptr = (uint16_t)0;

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
        return;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(args->host);

    psh.source_address = inet_addr(source_ip);
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));

    tcp_header->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

    // Trimitere packet
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        printf("Error: sendto() failed.\n");
        close(sockfd);
        return;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("Error setting SO_RCVTIMEO");
        close(sockfd);
        return;
    } 

    // Primire raspuns
    char recv_buf[4096];
    struct sockaddr_in recv_src;
    socklen_t recv_src_len = sizeof(recv_src);

    int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_src, &recv_src_len);

    if (recv_len < 0)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            if (args->syn_scan == 1)
            {
                printf("PORT: %d\tSTARE: FILTERED (timeout) \n", port);
                return;
            }
            if (args->fin_scan == 1 || args->xmas_scan == 1 || args->null_scan == 1)
            {
                printf("PORT: %d\tSTARE: OPEN|FILTERED \n", port);
                return;
            }
        }
        else
        {
            perror("Error: recvfrom() failed.");
        }

        close(sockfd);
        return;
    }

    ip_header = (struct iphdr *)recv_buf;
    tcp_header = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));

    fflush(stdout);
    if (args->syn_scan == 1)
    {
        if (tcp_header->syn == 1 && tcp_header->ack == 1 && tcp_header->fin == 0 && tcp_header->rst == 0 && tcp_header->psh == 0 && tcp_header->urg == 0)
        {
            if (args->verbose == 1)
            {
                struct servent *s = getservbyport(htons(port), "tcp");
                if (s)
                    printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
            }
            else
            {
                printf("PORT: %d\tSTARE: OPEN \n", port);
            }
        }
        else if (tcp_header->rst == 1)
        {
            printf("PORT: %d\t CLOSED\n", port);
        }
        else
        {
            printf("PORT: %d\tFILTERED\n", port);
        }
    }
    else if (args->xmas_scan)
    {
        if (tcp_header->rst == 1 && tcp_header->ack == 1)
        {
            if (args->verbose == 1)
            {
                struct servent *s = getservbyport(htons(port), "tcp");
                if (s)
                    printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
            }
            else
            {
                printf("PORT: %d\tSTARE: OPEN\n", port);
            }
        }
        else if (tcp_header->rst == 1)
        {
            printf("PORT: %d\t CLOSED\n", port);
        }
        else
        {
            printf("PORT: %d\tSTARE: OPEN|FILTERED \n", port);
        }
    }
    else if (args->fin_scan)
    {
        if (tcp_header->fin == 1 && tcp_header->ack == 1)
        {
            if (args->verbose == 1)
            {
                struct servent *s = getservbyport(htons(port), "tcp");
                if (s)
                    printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
            }
            else
            {
                printf("PORT: %d\tSTARE: OPEN\n", port);
            }
        }
        else if (tcp_header->rst == 1)
        {
            printf("PORT: %d\t CLOSED\n", port);
        }
        else
        {
            printf("PORT: %d\tSTARE: OPEN|FILTERED \n", port);
        }
    }
    else if (args->null_scan)
    {
        if (tcp_header->rst == 1)
        {
            printf("PORT: %d\t CLOSED\n", port);
        }
        else
        {
            printf("PORT: %d\tSTARE: OPEN|FILTERED \n", port);
        }
    }
    else if (args->ack_scan || args->window_scan)
    {
        if (args->window_scan)
        {
            if (tcp_header->window == 0)
            {
                printf("PORT: %d\tSTARE: CLOSED\n", port);
            }
            else
            {
                if (args->verbose == 1)
                {
                    struct servent *s = getservbyport(htons(port), "tcp");
                    if (s)
                        printf("PORT: %d\tSTARE: OPEN\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
                }
                else
                {
                    printf("PORT: %d\tSTARE: OPEN\n", port);
                }
            }
        }
        else if (args->ack_scan)
        {
            if (tcp_header->rst == 1)
            {
                if (args->verbose == 1)
                {
                    struct servent *s = getservbyport(htons(port), "tcp");
                    if (s)
                        printf("PORT: %d\tSTARE: UNFILTERED\t PROTOCOL:%s\t SERVICE:%s\t\n", port, s->s_proto, s->s_name);
                }
                else
                {
                    printf("PORT: %d\tSTARE: UNFILTERED\n", port);
                }
            }
            else
            {
                printf("PORT: %d\tSTARE: FILTERED \n", port);
            }
        }
    }

    close(sockfd);
}

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
        if (args->tcp_scan)
        {
            TCP_scan(args, port);
        }
        else if (args->udp_scan)
        {
            UDP_scan(args, port);
        }
        else if(args->fin_scan || args->xmas_scan || args->window_scan || args->ack_scan || args->null_scan || args->syn_scan)
        {
            SYN_NULL_FIN_XMAS_scan(args, port);
        }
        else 
        {
            CustomScan(args, port);
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

    if (user_args.threads > (user_args.end_port - user_args.start_port + 1))
    {
        user_args.threads = user_args.end_port - user_args.start_port + 1;
    }

    // Creare thread-uri
    for (thread_id = 0; thread_id < user_args.threads; thread_id++)
    {
        opt[thread_id].thread_id = thread_id;
        if (thread_id == user_args.threads - 1) // ultimul thread ia si porturile ramase
        {
            opt[thread_id].start = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id);
            opt[thread_id].end = user_args.end_port;
        }
        else
        {
            opt[thread_id].start = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id);
            opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id + 1) - 1;
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
        opt[thread_id].ack_scan = user_args.ack_scan;
        opt[thread_id].window_scan = user_args.window_scan;
        strcpy(opt[thread_id].custom, user_args.custom);

        if (pthread_create(&threads[thread_id], NULL, thread_routine, &opt[thread_id]))
        {
            perror("pthread_create");
            return;
        }
    }

    for (thread_id = 0; thread_id < user_args.threads; thread_id++)
    {
        pthread_join(threads[thread_id], NULL);
    }
}

int main(int argc, char **argv)
{
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

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
        return 0;
    }

    bzero(user_args.host, sizeof(user_args.host)); // face user_args->host 0

    strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));

    if (user_args.udp_scan)
    {
        printf("UDP scan\n");
    }
    else if (user_args.tcp_scan)
    {
        printf("TCP Connect scan\n");
    }
    else if (user_args.syn_scan)
    {
        printf("TCP SYN scan\n");
    }
    else if (user_args.xmas_scan)
    {
        printf("TCP XMAS scan\n");
    }
    else if (user_args.null_scan)
    {
        printf("TCP NULL scan\n");
    }
    else if (user_args.fin_scan)
    {
        printf("TCP FIN scan\n");
    }
    else if (user_args.ack_scan)
    {
        printf("TCP ACK scan\n");
    }
    else if (user_args.window_scan)
    {
        printf("TCP WINDOW scan\n");
    }
    else
    {
        printf("CUSTOM scan\n");
    }
    printf("Scanning %s\n\n", user_args.host);
    create_thread(user_args);

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double total_time = (end_time.tv_sec - start_time.tv_sec) +
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("\nScan duration: %.2f seconds\n", total_time);
    return 0;
}