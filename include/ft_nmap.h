#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/poll.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <pcap.h>

#define B_SYN  0b00000001
#define B_NULL 0b00000010
#define B_ACK  0b00000100
#define B_FIN  0b00001000
#define B_XMAS 0b00010000
#define B_UDP  0b00100000
#define B_RST  0b01000000

#define OPT_HELP    0
#define OPT_PORTS   1
#define OPT_HOST    2
#define OPT_FILE    3
#define OPT_SPEEDUP 4
#define OPT_SCAN    5

#define OPEN            "open"
#define CLOSE           "close"
#define FILTERED        "filtered"
#define OPEN_FILTERED   "open|filtered"
#define UNKNOWN         "unknown"

#define TOT_TYPE    6
#define MAX_THREAD  250
#define MAX_PORT    1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

enum e_type
{
    E_SYN,
    E_NULL,
    E_ACK,
    E_FIN,
    E_XMAS,
    E_UDP,
};

typedef struct  s_result
{
    int port;
    char service[NI_MAXSERV];
    char status[TOT_TYPE][32];
}               t_result;

typedef struct  s_host
{
    char dest_str[NI_MAXHOST];
    char ipdest_str[INET_ADDRSTRLEN];
    struct sockaddr_in ipdest;
    t_result *result;
    struct s_host *next;
}               t_host;

typedef struct  s_thread_args
{
    int snd_sock;
    pcap_t *handle;
    int *ports;
    int nports;
}               t_thread_args;

typedef struct  s_types
{
    char    name[16];
    uint8_t bit;
}               t_types;

typedef struct  s_info
{
    char dev[128];
    char ipsrc_str[INET_ADDRSTRLEN];
    struct sockaddr_in ipsrc;
    uint8_t type;
    t_host *hosts;
    t_host *host;
    int ports[MAX_PORT+1];
    int nports;
    int nthreads;
    t_thread_args thread_args[MAX_THREAD];
    t_types set_types[TOT_TYPE];
    pthread_mutex_t m_result;
}               t_info;

extern t_info info;

// main.c
int     usage(void);

// options.c
int     get_args(int ac, char **av);

// utils.c
t_host  *create_node_host(char *str);
int     add_node_host(t_host *host);
void    free_hosts(void);

#endif