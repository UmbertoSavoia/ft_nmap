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
    memcpy(info.set_types[E_NULL].name, "NULL", 5);
    info.set_types[E_NULL].bit = B_NULL;
    memcpy(info.set_types[E_ACK].name, "ACK", 4);
    info.set_types[E_ACK].bit = B_ACK;
    memcpy(info.set_types[E_FIN].name, "FIN", 4);
    info.set_types[E_FIN].bit = B_FIN;
    memcpy(info.set_types[E_XMAS].name, "XMAS", 5);
    info.set_types[E_XMAS].bit = B_XMAS;
    memcpy(info.set_types[E_UDP].name, "UDP", 4);
    info.set_types[E_UDP].bit = B_UDP;
}

int     cleen_exit(int ret)
{
    free_hosts();
    return ret;
}

int     main(int ac, char **av)
{
    if (ac < 2)
        return usage();
    set_types_array();
    if (get_args(ac, av) < 0)
        return cleen_exit(1);
    for (info.host = info.hosts; info.host; info.host = info.host->next) {
        
    }
    cleen_exit(0);
}