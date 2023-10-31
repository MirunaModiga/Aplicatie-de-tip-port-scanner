#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

int main(int argc , char **argv)
{
    struct hostent *host;
    int err, portno , sock , start , end;
    char hostname[100];
    struct sockaddr_in sa;
    struct timeval start_time;
    struct timeval end_time;

    printf("Enter hostname or IP : ");
    gets(hostname);

    printf("Select scan option:\n");
    printf("1. Scan a specific port\n");
    printf("2. Scan a range of ports\n");
    printf("3. Scan all ports (1-1024)\n");
    int scan_option;
    scanf("%d", &scan_option);

    if (scan_option == 1) {
        printf("Enter port number to scan: ");
        scanf("%d", &start);
        end = start;
    } else if (scan_option == 2) {
        printf("Enter start port number: ");
        scanf("%d" , &start);
        printf("Enter end port number: ");
        scanf("%d" , &end);
    } else if (scan_option == 3) {
        start = 1;
        end = 1024;
    } else {
        printf("Invalid scan option\n");
        return 1;
    }

    // structura adresa-port
    strncpy((char*)&sa , "" , sizeof sa);
    sa.sin_family = AF_INET;   //familia de adrese

    if(isdigit(hostname[0])) {
        printf("Doing inet_addr...");
        sa.sin_addr.s_addr = inet_addr(hostname);
        printf("Done\n");
    } else if ((host = gethostbyname(hostname)) != 0) {
        printf("Doing gethostbyname...");
        strncpy((char*)&sa.sin_addr , (char*)host->h_addr , sizeof sa.sin_addr);
        printf("Done\n");
    } else {
        herror(hostname);
        exit(2);
    }

    printf("Starting the port scan loop : \n\n");
    
    printf("IP address: %s\n", inet_ntoa(sa.sin_addr));
        printf("PORT\t\tSTATUS\t\tSERVICE\t\tPROTOCOL\n");
        printf("------------------------------------------------------------\n");
        
    gettimeofday(&start_time, NULL);
    for (portno = start; portno <= end; portno++) {
        sa.sin_port = htons(portno);    // htons = big endian = host to network short
        sock = socket(AF_INET , SOCK_STREAM , 0);    // socket TCP

        if (sock < 0) {
            perror("\nERROR opening socket");
            exit(1);
        }
        err = connect(sock , (struct sockaddr*)&sa , sizeof sa);

        // Not connected
        if (err < 0) {
            //printf("%s %-5d %s\r" , hostname , portno, strerror(errno));
            fflush(stdout);
        }
        // Connected
        else {
            struct servent *service_entry = getservbyport(htons(portno), NULL);
            if (service_entry != NULL) {
                printf("%-5d\t\topen\t\t%s\t\t%s\n", portno, service_entry->s_name, service_entry->s_proto);
            } else {
                printf("%-5d open (unknown)\n", portno);
            }
        }
        close(sock);
    }
    gettimeofday(&end_time, NULL);
    int sec;
    int usec;

    // time cost
    if (end_time.tv_usec < start_time.tv_usec) {
        usec = end_time.tv_usec - start_time.tv_usec + 1000000;
        end_time.tv_sec--;
    }
    else {
        usec = end_time.tv_usec - start_time.tv_usec;
    }
    sec = end_time.tv_sec - start_time.tv_sec;
    printf("Scan completed in %d.%d seconds\n", sec,usec);

    printf("\r");
    fflush(stdout);
    return(0);
}

