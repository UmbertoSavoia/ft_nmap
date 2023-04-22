#include "ft_nmap.h"
#include "ft_getopt.h"

t_info info = {0};

int     usage(void)
{
    char msg[] = "\n"
                 "ft_nmap [OPTIONS]\n"
                 " --help      Print this help screen\n"
                 " --ports     ports to scan (1-10 or 1,2,3 or 1,5-15)\n"
                 " --host      ip addresses in dot format or hostname to scan\n"
                 " --file      file name containing IP addresses or hostname to scan\n"
                 " --speedup   [250 max] number of parallel threads to use\n"
                 " --scan      SYN/NULL/FIN/XMAS/ACK/UDP\n";
    fwrite(msg, sizeof(msg), 1, stderr);
    return 1;
}

void    set_types_array(void)
{
    memcpy(info.set_types[E_SYN].name, "SYN", 4);
    info.set_types[E_SYN].bit = B_SYN;
    info.set_types[E_SYN].idx = E_SYN;
    memcpy(info.set_types[E_NULL].name, "NULL", 5);
    info.set_types[E_NULL].bit = B_NULL;
    info.set_types[E_NULL].idx = E_NULL;
    memcpy(info.set_types[E_ACK].name, "ACK", 4);
    info.set_types[E_ACK].bit = B_ACK;
    info.set_types[E_ACK].idx = E_ACK;
    memcpy(info.set_types[E_FIN].name, "FIN", 4);
    info.set_types[E_FIN].bit = B_FIN;
    info.set_types[E_FIN].idx = E_FIN;
    memcpy(info.set_types[E_XMAS].name, "XMAS", 5);
    info.set_types[E_XMAS].bit = B_XMAS;
    info.set_types[E_XMAS].idx = E_XMAS;
    memcpy(info.set_types[E_UDP].name, "UDP", 4);
    info.set_types[E_UDP].bit = B_UDP;
    info.set_types[E_UDP].idx = E_UDP;
}

int     cleen_exit(int ret)
{
    free_hosts();
    pthread_mutex_destroy(&info.m_result);
    return ret;
}

void    set_tasks_for_thread(void)
{
    int tasks = info.nports / info.nthreads;
    int r_tasks = info.nports % info.nthreads;
    int passed = 0, pass = 0;

    for (int i = 0; i < info.nthreads; ++i) {
        pass = tasks;
        if (r_tasks > 0) { ++pass; --r_tasks; }
        info.thread_args[i].nports = pass;
        info.thread_args[i].ports = info.ports+passed;
        passed += pass;
    }
}

void    resolve_dns_hosts(void)
{
    t_host *t = 0;

    for (t = info.hosts; t; t = t->next) {
        getnameinfo((struct sockaddr *)&(t->ipdest), sizeof(struct sockaddr),
                t->dns, sizeof(t->dns), 0, 0, NI_IDN);
    }
}

int     main(int ac, char **av)
{
    struct timeval start = {0}, end = {0};
    double delta = 0;

    if (ac < 2)
        return usage();
    set_types_array();
    if (get_args(ac, av) < 0)
        return cleen_exit(1);
    if (find_dev() < 0)
        return cleen_exit(1);
    resolve_dns_hosts();
    set_tasks_for_thread();
    pthread_mutex_init(&info.m_result, 0);
    print_header();
    gettimeofday(&start, 0);
    for (info.host = info.hosts; info.host; info.host = info.host->next) {
        for (int i = 0; i < info.nthreads; ++i) {
            int *ident = malloc(sizeof(int));
            *ident = i;
            pthread_create(&(info.thread_args[i].tid), 0, thread_scan, (void *)ident);
        }
        for (int i = 0; i < info.nthreads; ++i)
            pthread_join(info.thread_args[i].tid, 0);
    }
    gettimeofday(&end, 0);
    delta = delta_time(&start, &end) / 1000;
    printf("\nScan took %f secs\n", delta);
    print_result();
    cleen_exit(0);
}