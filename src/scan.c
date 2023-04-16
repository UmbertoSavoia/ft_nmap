#include "ft_nmap.h"

int     get_info_serv(t_result *res, int port)
{
    struct servent *serv = getservbyport(htons(port), 0);

    if (!serv) {
        memcpy(res->service, UNKNOWN, strlen(UNKNOWN)+1);
    } else {
        memcpy(res->service, serv->s_name, strlen(serv->s_name)+1);
    }
    res->port = port;
    return 0;
}

int     set_pcap(int ident, int port)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char filter[1024] = {0};
    struct bpf_program fp;
    bpf_u_int32 ip, mask;

    if (!(info.thread_args[ident].handle = pcap_open_live(info.dev, IP_MAXPACKET, 1, 1000, errbuf))) {
        printf("Error: pcap_open_live: %s\n", errbuf);
        return -1;
    }
    if (pcap_lookupnet(info.dev, &ip, &mask, errbuf) < 0) {
        printf("Error: pcap_lookupnet: %s\n", errbuf);
        return -1;
    }
    snprintf(filter, sizeof(filter),
             (info.type & B_UDP) ?
             "(icmp and src port %d and src host %s and dst host %s)" :
             "(tcp and src port %d and src host %s and dst host %s)",
             port, info.host->ipdest_str, info.ipsrc_str);
    if (pcap_compile(info.thread_args[ident].handle, &fp, filter, 0, ip) < 0) {
        printf("Error: pcap_compile\n");
        return -1;
    }
    if (pcap_setfilter(info.thread_args[ident].handle, &fp)) {
        printf("Error: pcap_setfilter\n");
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

int     open_snd_sock(int ident)
{
    int on = 1;
    errno = 0;
    if ((info.thread_args[ident].snd_sock = socket(AF_INET,
                                                   SOCK_RAW,
                                              (info.type & B_UDP) ? IPPROTO_RAW : IPPROTO_TCP)) < 0) {
        printf("Error: %s\n", strerror(errno));
        return -1;
    }
    if (setsockopt(info.thread_args[ident].snd_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        printf("Error: setsockopt: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

uint16_t checksum(void *addr, int len)
{
    unsigned long checksum = 0;
    unsigned short *buf = addr;

    while (len > 1) {
        checksum += (unsigned short)*buf++;
        len -= sizeof(unsigned short);
    }
    if (len)
        checksum += *(unsigned char *)buf;
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    return (unsigned short)(~checksum);
}

void    prepare_packet_udp(uint8_t *packet, uint8_t type, int port)
{
    struct ip    *ip  = (struct ip *)packet;
    struct udphdr   *udp = (struct udphdr *)(packet + sizeof(struct ip));

    ip->ip_tos = 0;
    ip->ip_dst.s_addr = info.host->ipdest.sin_addr.s_addr;
    ip->ip_off = 0;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
    ip->ip_ttl = 64;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(getpid());
    udp->uh_sport = htons(getpid());
    udp->uh_dport = htons(port);
    udp->uh_ulen = htons((uint16_t)(sizeof(struct udphdr)));
    udp->uh_sum = 0;
}

void    prepare_packet_tcp(uint8_t *packet, uint8_t type, int port)
{
    struct pseudo_header psh = {0};
    struct ip *ip = (struct ip *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip));

    ip->ip_tos = 0;
    ip->ip_dst.s_addr = info.host->ipdest.sin_addr.s_addr;
    ip->ip_src.s_addr = info.ipsrc.sin_addr.s_addr;
    ip->ip_off = 0;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip->ip_ttl = 64;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(getpid());
    ip->ip_sum = 0;
    ip->ip_sum = checksum(ip, sizeof(struct ip));

    tcp->source = htons(getpid());
    tcp->dest = htons(port);
    tcp->seq = htons(0);
    tcp->ack_seq = 0;
    tcp->doff = sizeof(struct tcphdr) >> 2;
    tcp->fin = (type & B_FIN || type & B_XMAS) ? 1 : 0;
    tcp->syn = (type & B_SYN) ? 1 : 0;
    tcp->rst = (type & B_RST) ? 1 : 0;
    tcp->psh = (type & B_XMAS) ? 1 : 0;
    tcp->ack = (type & B_ACK) ? 1 : 0;
    tcp->urg = (type & B_XMAS) ? 1 : 0;
    tcp->window = htons(UINT16_MAX);
    tcp->urg_ptr = 0;
    tcp->th_sum = 0;

    psh.source_address = info.ipsrc.sin_addr.s_addr;
    psh.dest_address = info.host->ipdest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&(psh.tcp), tcp, sizeof(struct tcphdr));

    tcp->th_sum = checksum(&psh, sizeof(struct pseudo_header));
}

int     send_packet(int ident, int port, uint8_t type)
{
    uint8_t packet[IP_MAXPACKET] = {0};
    struct pollfd fds[1];
    uint32_t tot_len_packet = sizeof(struct ip) + sizeof(struct tcphdr);
    errno = 0;

    if (type & B_UDP) {
        prepare_packet_udp(packet, type, port);
    } else {
        prepare_packet_tcp(packet, type, port);
    }

    fds[0].fd = info.thread_args[ident].snd_sock;
    fds[0].events = POLLOUT;

    struct in_addr sin_addr = { .s_addr = info.host->ipdest.sin_addr.s_addr };
    struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr = sin_addr,
            .sin_port = htons(port)
    };

    if (poll(fds, 1, -1) < 0) {
        printf("Error: poll: %s\n", strerror(errno));
        return -1;
    }
    if (fds[0].revents & POLLOUT) {
        if(sendto(info.thread_args[ident].snd_sock, packet, tot_len_packet, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("Error: sendto: %s\n", strerror(errno));
            return -1;
        }
    } else if (fds[0].revents & POLLERR) {
        printf("Error: poll: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int     handler_icmp_type(t_result *res, t_types *set, struct icmp *icmp)
{
    if (icmp->icmp_type == ICMP_DEST_UNREACH &&
        (icmp->icmp_code == ICMP_UNREACH_PORT || icmp->icmp_code == ICMP_UNREACH_FILTER_PROHIB)) {
        memcpy(res->status[set->idx], CLOSE, strlen(CLOSE)+1);
    }
}

int     handler_tcp_type(int ident, t_result *res, t_types *set, struct tcphdr *tcp)
{
    if (tcp->ack && tcp->syn) {
        memcpy(res->status[set->idx], OPEN, strlen(OPEN)+1);
    } else {
        memcpy(res->status[set->idx], CLOSE, strlen(CLOSE)+1);
    }
    send_packet(ident, res->port, B_RST);
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    t_callback *arg = (t_callback *)user;
    struct ip       *ip  = (struct ip *)(ETH_HLEN + bytes);
    struct tcphdr   *tcp = (struct tcphdr *)(ETH_HLEN + bytes + sizeof(struct ip));
    struct icmp     *icmp = (struct icmp *)(ETH_HLEN + bytes + sizeof(struct ip));

    if (ip->ip_p == IPPROTO_TCP && (arg->set->bit & (B_SYN|B_ACK|B_FIN|B_NULL|B_XMAS)))
        handler_tcp_type(arg->ident, arg->res, arg->set, tcp);
    else if (ip->ip_p == IPPROTO_ICMP && (arg->set->bit & B_UDP))
        handler_icmp_type(arg->res, arg->set, icmp);
}

int     recv_packet(int ident, t_result *res, uint8_t type, t_types *set)
{
    struct pollfd fds[1];
    int rcv_sock = 0, ret = 0;
    t_callback arg = { .res = res, .ident = ident, .set = set };

    if ((rcv_sock = pcap_get_selectable_fd(info.thread_args[ident].handle)) < 0) {
        printf("Error: pcap_get_selectable_fd\n");
        return -1;
    }

    fds[0].fd = rcv_sock;
    fds[0].events = POLLIN;
    while ((ret = poll(fds, 1, 2000)) > 0) {
        if (fds[0].revents & POLLIN) {
            if (pcap_dispatch(info.thread_args[ident].handle, -1, callback, (u_char *)(&arg))) {
                return 1;
            }
        } else if (fds[0].revents & POLLERR) {
            printf("Error: poll: %s\n", strerror(errno));
            return -1;
        }
    }

    if (ret == 0 && type & (B_SYN|B_ACK)) {
        memcpy(res->status[set->idx], FILTERED, strlen(FILTERED)+1);
    } else if (ret == 0 && type & (B_FIN|B_NULL|B_XMAS|B_UDP)) {
        memcpy(res->status[set->idx], OPEN_FILTERED, strlen(OPEN_FILTERED)+1);
    } else if (ret < 0) {
        printf("Error poll\n");
    }
    return ret;
}

void    *thread_scan (void *p_ident)
{
    int ident = *(int *)p_ident;

    for (int i = 0; i < info.thread_args[ident].nports; ++i) {
        int port = *(info.thread_args[ident].ports+i);
        t_result *res = calloc(1, sizeof(t_result));
        get_info_serv(res, port);
        for (int t = 0; t < TOT_TYPE; ++t) {
            if (info.type & info.set_types[t].bit) {
                write(1, ".", 1);
                if (open_snd_sock(ident) < 0) {
                    free(p_ident); return 0;
                }
                if (set_pcap(ident, port) < 0) {
                    free(p_ident); return 0;
                }
                if (send_packet(ident, port, info.set_types[t].bit) < 0) {
                    free(p_ident); close(info.thread_args[ident].snd_sock); return 0;
                }
                recv_packet(ident, res, info.set_types[t].bit, &(info.set_types[t]));

                close(info.thread_args[ident].snd_sock);
                pcap_close(info.thread_args[ident].handle);
            }
        }
        add_node_result(info.host, res);
    }
    free(p_ident);
    return 0;
}