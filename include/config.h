#pragma once

#include "logger.h"

#define CONFIG__DEFAULT_CFG_PATH "/root/radius-server/conf/radius.conf"

#define CONFIG__LISTEN "0.0.0.0"
#define CONFIG__AUTH_PORT 1812
#define CONFIG__ACCT_PORT 1813
#define CONFIG__DB_FILE "radius.db"
#define CONFIG__LOG_FILE "radius.log"
#define CONFIG__LOG_LEVEL LL_INFO

typedef struct {
    char* listen;
    uint16_t auth_port;
    uint16_t acct_port;
    char* db_file;
    char* log_file;
    log_level_t log_level;
} config_t;

bool init_config(const char* config_path, config_t* config);
void deinit_config(config_t *config);
