#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "common.h"
#include "config.h"

#define COMMENT_CHAR '#'
#define PARSE_ERROR_FMT "Error parse config [%s]: %s\n"


bool init_config(const char* config_path, config_t* config) {
    FILE* config_file = fopen(config_path, "r");

    if (!config_file) {
        fprintf(stderr, "%s: %s\n", strerror(errno), config_path);
        return false;
    }

    char* line = NULL;
    size_t n = 0;
    bool is_success = true;

    while (getline(&line, &n, config_file) != -1) {
        if (line[0] != NEW_LINE && line[0] != COMMENT_CHAR) {
            char* ptr = strtok(line, "= ");
            char* name = ptr;
            ptr = strtok(NULL, "= ");
            char* value = ptr;

            char* new_line = NULL;
            if ((new_line = strchr(value, NEW_LINE))) {
                *new_line = NULL_TERM;
            }

            if (strcmp(name, "listen") == 0) {
                uint32_t ipv4;
                is_success = (bool) inet_pton(AF_INET, value, &ipv4);
                if (is_success && !(config->listen = copy_str(value))) {
                    is_success = false;
                }
            }

            else if (strcmp(name, "auth_port") == 0) {
                is_success = str_to_uint16(value, &config->auth_port);
            }

            else if (strcmp(name, "acct_port") == 0) {
                is_success = str_to_uint16(value, &config->acct_port);
            }

            else if (strcmp(name, "db_file") == 0) {
                if(strlen(value) > MAX_PATH_LEN || !(config->db_file = copy_str(value))) {
                    is_success = false;
                }
            }

            else if (strcmp(name, "log_file") == 0 ) {
                if(strlen(value) > MAX_PATH_LEN || !(config->log_file = copy_str(value))) {
                    is_success = false;
                }
            }

            else if (strcmp(name, "log_level") == 0) {
                uint8_t log_level = LL_DEBUG;
                for (; log_level <= LL_FATAL; ++log_level) {
                    if (strcasecmp(value, get_log_level_str(log_level)) == 0) {
                        config->log_level = log_level;
                        break;
                    }
                }

                if (log_level > LL_FATAL) {
                    is_success = false;
                }
            }

            if (!is_success) {
                log_fatal(PARSE_ERROR_FMT, name, value);
                deinit_config(config);
                fclose(config_file);
                return false;
            }
        }
    }

    if (!config->listen) {
        config->listen = copy_str(CONFIG__LISTEN);
    }
    if (config->auth_port == 0) {
        config->auth_port = CONFIG__AUTH_PORT;
    }
    if (config->acct_port == 0) {
        config->acct_port = CONFIG__ACCT_PORT;
    }
    if (!config->db_file) {
        config->db_file = copy_str(CONFIG__DB_FILE);
    }
    if (!config->log_file) {
        config->log_file = copy_str(CONFIG__LOG_FILE);
    }
    if (config->log_level == LL_UNDEFINED) {
        config->log_level = CONFIG__LOG_LEVEL;
    }

    if (!config->listen || !config->db_file || !config->log_file) {
        deinit_config(config);
        fclose(config_file);
        return false;
    }

    fclose(config_file);
    return true;
}

void deinit_config(config_t *config) {
    if (!config) {
        return;
    }
    if (config->listen) {
        free(config->listen);
        config->listen = NULL;
    }
    if (config->db_file) {
        free(config->db_file);
        config->db_file = NULL;
    }
    if (config->log_file) {
        free(config->log_file);
        config->log_file = NULL;
    }
}
