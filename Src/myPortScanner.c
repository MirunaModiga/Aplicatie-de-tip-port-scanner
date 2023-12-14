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

uint16_t checksum(uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

uint16_t tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    struct pseudo_header
    {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;

    pseudo_header.source_address = ip_header->saddr;
    pseudo_header.dest_address = ip_header->daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

    int total_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    uint16_t *buff = malloc(total_len);
    memcpy(buff, &pseudo_header, sizeof(struct pseudo_header));
    memcpy(buff + sizeof(struct pseudo_header) / sizeof(uint16_t), tcp_header, sizeof(struct tcphdr));

    uint16_t checksum_result = checksum(buff, total_len);
    free(buff);

    return checksum_result;
}

int get_local_ip(char *source_ip)
{
    const char *google_dns_server = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(-1);
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
    if (p != NULL)
    {
        printf("Local ip is : %s \n", buffer);
    }

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
    else
    {
        if (errno == ECONNREFUSED)
        {
            printf("PORT: %d\tSTARE: CLOSED\n", port);
        }
        else if (errno == ETIMEDOUT)
        {
            printf("PORT: %d\tSTARE: FILTERED\n", port);
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

void SYN_scan(struct thread_options *args, int port)
{
    int sockfd;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char packet[5000];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    char source_ip[20];
    get_local_ip(source_ip); /*aflare IP propriu*/

    /*IP header*/
    ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(args->host);

    // Calculate IP header checksum
    ip_header->check = 0;
    ip_header->check = checksum((uint16_t *)ip_header, sizeof(struct iphdr));

    /*TCP header*/
    tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp_header->source = htons(2500);
    tcp_header->dest = htons(port);
    tcp_header->seq = random();
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->ack = 0;
    tcp_header->fin = 0;
    tcp_header->psh = 0;
    tcp_header->rst = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("Error setting IP_HDRINCL. Error number: %d. Error message: %s \n", errno, strerror(errno));
        exit(-1);
    }

    // Calculate TCP header checksum
    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(args->host);

    /*Trimitere packet*/
    if (sendto(sockfd, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        printf("Error: sendto() failed.\n");
        close(sockfd);
        exit(-1);
    }

    printf("Packet sent.\n");

    /*Asteptare raspuns*/
    fd_set read_fds;
    struct timeval timeout;
    int ret;

    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    timeout.tv_sec = 15;
    timeout.tv_usec = 0;

    ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

    if (ret == 0)
    {
        printf("Error: Timeout waiting for response.\n");
        close(sockfd);
        exit(-1);
    }
    else if (ret < 0)
    {
        printf("Error: select() failed.\n");
        close(sockfd);
        exit(-1);
    }

    /*Primire raspuns*/
    char recv_buf[1024];
    struct sockaddr_in recv_src;
    socklen_t recv_src_len;
    int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_src, &recv_src_len);

    if (recv_len < 0)
    {
        printf("Error: recvfrom() failed.\n");
        close(sockfd);
        exit(-1);
    }

    /*Verificam daca pachetul primit este ceea ce ne dorim*/
    ip_header = (struct iphdr *)recv_buf;
    tcp_header = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));

    if (tcp_header->syn == 1 && tcp_header->ack == 1)
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
        printf("invalid SYN-ACK response.\n");
        close(sockfd);
        exit(-1);
    }
    close(sockfd);
}

void NULL_scan() {}

void XMAS_scan() {}

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
            TCP_scan(args, port);
        }
        else if (args->udp_scan)
        {
            UDP_scan(args, port);
        }
        else if (args->syn_scan)
        {
            SYN_scan(args, port);
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
        if (thread_id == user_args.threads - 1) // ultimul thread ia si porturile ramase
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
            perror("pthread_create");
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
    clock_t start_time, end_time;
    start_time = clock();
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

    if (user_args.udp_scan)
    {
        printf("UDP scan\n");
    }
    else
    {
        printf("TCP scan\n");
    }
    printf("Scanning %s\n\n", user_args.host);
    create_thread(user_args);

    end_time = clock();
    double total_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("\nScan duration: %.2f seconds\n", total_time);

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