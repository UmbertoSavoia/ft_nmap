#include "ft_nmap.h"

void    print_header(void)
{
    printf("Scan Configurations\n"
           "Source network interface: %s\n"
           "Source IP address: %s\n"
           "Number of threads: %d\n"
           "Number of ports to scan: %d\n"
           "Scans to be performed: ",
           info.dev, info.ipsrc_str, info.nthreads, info.nports);
    for (int i = 0; i < TOT_TYPE; ++i)
        if (info.type & info.set_types[i].bit)
            printf("%s ", info.set_types[i].name);
    printf("\n"
           "Scanning...\n");
}

uint8_t check_if_one_is_open(void)
{
    for (t_result *res = info.host->results; res; res = res->next) {
        for (int i = 0; i < TOT_TYPE; ++i) {
            if (info.type & info.set_types[i].bit) {
                if (res->open) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

uint8_t check_if_one_is_close_filtered(void)
{
    for (t_result *res = info.host->results; res; res = res->next) {
        for (int i = 0; i < TOT_TYPE; ++i) {
            if (info.type & info.set_types[i].bit) {
                if (!(res->open)) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

void    print_result_port_line(uint8_t print_open)
{
    int padding = 0, n_type = 0;

    if (print_open) {
        printf("Open ports:\n");
    } else {
        printf("Closed/Filtered ports:\n");
    }
    printf("%-8s %-20s %s\n"
           "-------------------------------------------------------\n",
           "Port", "Service", "State");
    for (t_result *res = info.host->results; res; res = res->next) {
        if (res->open == print_open) {
            n_type = 0;
            padding = printf("%-8d %-20s ", res->port, res->service);
            for (int i = 0; i < TOT_TYPE; ++i) {
                if (info.type & info.set_types[i].bit) {
                    if (n_type == 3) {
                        printf("\n%*c", padding, ' ');
                    }
                    printf("%s(%s) ", info.set_types[i].name, res->status[info.set_types[i].idx]);
                    ++n_type;
                }
            }
            printf("\n");
        }
    }
    printf("\n");
}

void    print_result(void)
{
    for (info.host = info.hosts; info.host; info.host = info.host->next) {
        printf("\n"
               "Target: %s - %s ",
               info.host->dest_str, info.host->ipdest_str, info.host->r_dns);
        if (!(info.no_dns))
            printf("(%s)\n", info.host->r_dns);
        else
            printf("\n");

        if (check_if_one_is_open())
            print_result_port_line(1);

        if (!info.only_open && check_if_one_is_close_filtered())
            print_result_port_line(0);
    }
}