#include "ft_nmap.h"

int     find_dev(void)
{
    errno = 0;
    struct ifaddrs *ifap = 0;

    if (getifaddrs(&ifap) < 0) {
        printf("Error: %s\n", strerror(errno));
        return -1;
    }
    struct ifaddrs *tmp = ifap;
    while (ifap) {
        if ((ifap->ifa_flags & (IFF_UP | IFF_RUNNING))
            && !(ifap->ifa_flags & IFF_LOOPBACK)
            && ifap->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *)ifap->ifa_addr;
            memcpy(info.dev, ifap->ifa_name, strlen(ifap->ifa_name)+1);
            memcpy(&(info.ipsrc), a, sizeof(struct sockaddr_in));
            memcpy(info.ipsrc_str, inet_ntoa(a->sin_addr), 15);
            break;
        }
        ifap = ifap->ifa_next;
    }
    freeifaddrs(tmp);
    return 0;
}

int     resolve_destination(char *str, t_host *host)
{
    int error = 0, on = 1, sock = 0;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo_list = 0, *tmp = 0;
    errno = 0;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME;

    if ((error = getaddrinfo(str, 0, &hints, &addrinfo_list))) {
        printf("Error: %s: %s\n", str, gai_strerror(error));
        return -2;
    }
    for (tmp = addrinfo_list; tmp; tmp = tmp->ai_next) {
        if ((sock = socket(AF_INET, SOCK_RAW,
                                     (info.type & B_UDP) ? IPPROTO_RAW : IPPROTO_TCP)) >= 0)
            break;
    }
    if ((sock < 0) || !tmp) {
        printf("Error: %s\n", strerror(errno));
        freeaddrinfo(addrinfo_list);
        return -1;
    }
    errno = 0;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        return printf("Error: setsockopt: %s\n", strerror(errno));
    }
    memcpy(&(host->dest_str), str, strlen(str)+1);
    memcpy(&(host->ipdest), (struct sockaddr_in *)tmp->ai_addr, sizeof(struct sockaddr_in));
    inet_ntop(tmp->ai_family, (void *)&(host->ipdest.sin_addr), host->ipdest_str, INET_ADDRSTRLEN);
    freeaddrinfo(addrinfo_list);
    close(sock);
    return 0;
}

t_host  *create_node_host(char *str)
{
    t_host *ret = 0;

    if (!(ret = calloc(1, sizeof(t_host))))
        return 0;
    if (resolve_destination(str, ret) < 0) {
        free(ret);
        return 0;
    }
    return ret;
}

void     add_node_result(t_host *host, t_result *result)
{
    pthread_mutex_lock(&info.m_result);

    result->next = host->results;
    host->results = result;

    pthread_mutex_unlock(&info.m_result);
}

void    free_results(t_result *results)
{
    t_result *r = 0;

    if (!results)
        return;
    while (results) {
        r = results;
        results = results->next;
        free(r);
    }
}

int    add_node_host(t_host *host)
{
    if (!host)
        return -1;

    host->next = info.hosts;
    info.hosts = host;
    return 0;
}

void    free_hosts(void)
{
    t_host *t = 0;

    while (info.hosts) {
        t = info.hosts;
        free_results(t->results);
        info.hosts = info.hosts->next;
        free(t);
    }
}

double  delta_time(struct timeval *t1, struct timeval *t2)
{
    return (t2->tv_sec - t1->tv_sec) * 1000.0 + (t2->tv_usec - t1->tv_usec) / 1000.0;
}