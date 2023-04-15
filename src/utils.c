#include "ft_nmap.h"

int     resolve_destination(char *str, t_host *host)
{
    int error = 0, on = 1, sock = 0;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo_list = 0, *tmp = 0;
    struct sockaddr_storage addr;
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
    memcpy(&(host->dest_str), str, strlen(str));
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

int    add_node_host(t_host *host)
{
    if (!host)
        return -1;
    if (!(info.hosts)) {
        info.hosts = host;
    } else {
        host->next = info.hosts;
        info.hosts = host;
    }
    return 0;
}

void    free_hosts(void)
{
    t_host *t = 0;

    while (info.hosts) {
        t = info.hosts;
        info.hosts = info.hosts->next;
        free(t);
    }
}