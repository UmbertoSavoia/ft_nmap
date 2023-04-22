#include "ft_nmap.h"
#include "ft_getopt.h"

void    shrink_ports(void)
{
    int support[MAX_PORT+1] = {0};
    int j = 0;

    memcpy(support, info.ports, (MAX_PORT+1)*sizeof(int));
    bzero(info.ports, ARRAY_SIZE(info.ports));
    for (int i = 0; i < MAX_PORT+1; ++i) {
        if (support[i]) {
            info.ports[j] = i;
            ++j;
        }
    }
}

int     set_ports_opt(char *str)
{
    uint64_t start = 0, end = 0;
    info.nports = 0;
    char *tok = strtok(str, ",");
    char *ptr = 0;

    while (tok) {
        if ((ptr = strchr(tok, '-'))) {
            start = strtoull(tok, 0, 10);
            end = strtoull(ptr+1, 0, 10);
            if (start > MAX_PORT || end > MAX_PORT)
                return -1;
            if (start > end) {
                start = start^end; end = start^end; start = end^start;
            }
            for (uint64_t i = start; start <= end; ++start) {
                if (!info.ports[start]) ++info.nports;
                info.ports[start] = 1;
            }
        } else {
            start = strtoull(tok, 0, 10);
            if (start > MAX_PORT)
                return -1;
            if (!info.ports[start]) ++info.nports;
            info.ports[start] = 1;
        }
        tok = strtok(0, ",");
    }
    if (info.nports)
        shrink_ports();
    return 0;
}

int     set_types(char *str)
{
    char *tok = strtok(str, ",");

    if (!tok) return -1;
    while (tok) {
        for (int i = 0; i < TOT_TYPE; ++i) {
            if (!memcmp(info.set_types[i].name, tok, strlen(info.set_types[i].name))) {
                info.type |= info.set_types[i].bit;
            }
        }
        tok = strtok(0, ",");
    }
    return 0;
}

int     read_host_from_file(char *file, char *exclude)
{
    errno = 0;
    int readed = 0, r = 0;
    char buf[NI_MAXHOST] = {0};
    int fd = open(file, O_RDONLY);
    int len_exclude = (exclude) ? strlen(exclude) : 0;

    if (fd < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
    }
    while ((r = read(fd, buf+readed, 1)) > 0) {
        if (readed+1 >= NI_MAXHOST) {
            close(fd);
            fwrite("Error: hostname too long\n", 25, 1, stderr);
            return -1;
        }
        if (*(buf+readed) == '\n') {
            *(buf+readed) = 0;
            if (exclude) {
                if (memcmp(exclude, buf, len_exclude)) {
                    if (add_node_host(create_node_host(buf)) < 0)
                        return -1;
                }
            } else {
                if (add_node_host(create_node_host(buf)) < 0)
                    return -1;
            }
            bzero(buf, sizeof(buf));
            readed = 0;
            continue;
        }
        readed += r;
    }
    close(fd);
    return 0;
}

int     get_args(int ac, char **av)
{
    t_option opt[] = {
            { .name = "help",    .has_arg = 0 },
            { .name = "ports",   .has_arg = 1 },
            { .name = "host",    .has_arg = 1 },
            { .name = "file",    .has_arg = 1 },
            { .name = "speedup", .has_arg = 1 },
            { .name = "scan",    .has_arg = 1 },
            { .name = "exclude", .has_arg = 1 },
            { .name = "n",       .has_arg = 0 },
            { .name = "ttl",     .has_arg = 1 },
            { .name = "open",    .has_arg = 0 },
    };
    ft_optind = 1;
    int idx = 0;
    int size_opt = ARRAY_SIZE(opt);
    char *host = 0, *file = 0, *exclude = 0;

    while ((idx = ft_getopt_long(ac, av, opt, size_opt)) != -1) {
        switch (idx) {
            case OPT_HELP:
                usage();
                exit(0);
            case OPT_PORTS:
                if (set_ports_opt(ft_optarg) < 0) {
                    fwrite("Invalid ports argument\n", 23, 1, stderr);
                    exit(1);
                }
                break;
            case OPT_HOST:
                host = ft_optarg;
                break;
            case OPT_FILE:
                file = ft_optarg;
                break;
            case OPT_SPEEDUP:
                info.nthreads = strtoull(ft_optarg, 0, 10);
                if (info.nthreads > MAX_THREAD || info.nthreads < 1) {
                    fwrite("Invalid speedup argument\n", 25, 1, stderr);
                    exit(1);
                }
                break;
            case OPT_SCAN:
                set_types(ft_optarg);
                break;
            case OPT_EXCLUDE:
                exclude = ft_optarg;
                break;
            case OPT_NODNS:
                info.no_dns = 1;
                break;
            case OPT_TTL:
                info.ttl = atoi(ft_optarg);
                break;
            case OPT_OPEN:
                info.only_open = 1;
                break;
        }
    }
    if (!info.nports) {
        for (int i = 1; i < MAX_PORT+1; ++i, ++(info.nports))
            info.ports[i] = 1;
        shrink_ports();
    }
    if (!info.type)
        info.type |= (B_SYN|B_NULL|B_ACK|B_FIN|B_XMAS|B_UDP);
    if (host) {
        if (add_node_host(create_node_host(host)) < 0)
            return -1;
    }
    if (file) {
        if (read_host_from_file(file, exclude) < 0)
            return -1;
    }
    if (!host && !file) {
        fwrite("Error: host or file is missing\n", 31, 1, stderr);
        return -1;
    }
    if (!info.nthreads)
        info.nthreads = 1;
    if (info.nthreads > info.nports)
        info.nthreads = info.nports;
    return 0;
}