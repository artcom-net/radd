#include <errno.h>
#include <stdlib.h>

#include "db.h"
#include "logger.h"
#include "nas.h"


const char* const _AUTH_TYPES_STR[] = {"password", "ip", "mac"};


nas_t* init_nas() {
    nas_t* nas = (nas_t*) alloc_memory(sizeof(nas_t));
    if (!nas) {
        return NULL;
    }
    return nas;
}

void dinit_nas(nas_t* nas) {
    if (!nas) {
        return;
    }
    if (nas->ip) {
        free(nas->ip);
        nas->ip = NULL;
    }
    if (nas->secret) {
        free(nas->secret);
        nas->secret = NULL;
    }
    free(nas);
    nas = NULL;
}

bool get_nas_by_ip(char* nas_ip, nas_t* nas) {
    sqlite3_stmt* stmt = prepare_statement("SELECT * FROM nas WHERE ip = ?1;");

    if (!stmt || !stmt_bind_str(stmt, 1, nas_ip)) {
        return false;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        nas->id = (uint32_t) sqlite3_column_int(stmt, 0);
        nas->ip = copy_str((char*) sqlite3_column_text(stmt, 1));
        nas->secret = copy_str((char*) sqlite3_column_text(stmt, 2));
        nas->auth_type = sqlite3_column_int(stmt, 3);

        if (!nas->ip || !nas->secret) {
            dinit_nas(nas);
            sqlite3_finalize(stmt);
            return false;
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

const char* const get_auth_type_str(auth_type_t auth_type) {
    switch (auth_type) {
        case PASSWORD_AUTH:
        case IP_AUTH:
        case MAC_AUTH:
            return _AUTH_TYPES_STR[auth_type];
        default:
            log_warning("Invalid auth_type = %d\n", auth_type);
            return NULL;
    }
}