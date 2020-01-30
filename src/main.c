/* RADIUS server */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "common.h"
#include "config.h"
#include "db.h"
#include "dictionary.h"
#include "logger.h"
#include "radius_server.h"


#define USAGE "Usage: radius [-h] [-v] [-l <ip_address>] [--auth-port <auth_port>] [--acct-port <acct_port>]\n"
#define VERSION "VERSION: 0.0.1\n"


void print_usage() {
    printf(USAGE);
}

void print_version() {
    printf(VERSION);
};

struct ip_ports {
    char* ip;
    uint16_t auth_port;
    uint16_t acct_port;
};


void parse_args(const int argc, const char** argv, struct ip_ports* _ip_ports) {
    int c;
    int longind = 0;
    struct option long_options[] = {
            {"auth-port", required_argument, NULL, 'a'},
            {"acct-port", required_argument, NULL, 'c'},
            {NULL, no_argument, NULL, 0}
    };

    while ((c = getopt_long(argc, (char* const*) argv, "hvl:", long_options, &longind)) != -1) {
        switch (c) {
            case 'l':
                _ip_ports->ip = optarg;
                break;
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            case 'v':
                print_version();
                exit(EXIT_SUCCESS);
            case 'a':
//                _ip_ports->auth_port = strport_to_uint16(optarg);
                if (!str_to_uint16(optarg, &(_ip_ports->auth_port))) {
                    printf("Invalid port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'c':
//                _ip_ports->acct_port = strport_to_uint16(optarg);
                if (!str_to_uint16(optarg, &(_ip_ports->acct_port))) {
                    printf("Invalid port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }
}

void _deinit_main_context() {
    dinit_logger();
    dinit_db();
    dinit_dictionary();
}

int main(const int argc, const char** argv) {
    config_t config = {0};

    if(!init_config(CONFIG__DEFAULT_CFG_PATH, &config)) {
        exit(EXIT_FAILURE);
    }

    if (!init_logger(config.log_file, config.log_level) || !init_db(config.db_file) || !init_dictionary()) {
        // TODO: Move it to another function.
        _deinit_main_context();
        deinit_config(&config);
        exit(EXIT_FAILURE);
    }

    log_info(
        "Starting the RADIUS server version 0.0.1. "
        "Configuration: listen=%s; auth_port=%u; acct_port=%u; db_file=%s log_file=%s log_level=%s\n",
        config.listen, config.auth_port, config.acct_port, config.db_file, config.log_file,
        get_log_level_str(config.log_level)
    );

    if (!start_radius_server(config.listen, config.auth_port, config.acct_port)) {
        _deinit_main_context();
        deinit_config(&config);
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
