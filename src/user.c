#include <errno.h>
#include <stdlib.h>

#include "db.h"
#include "logger.h"
#include "user.h"


user_t* init_user() {
    user_t* user = (user_t*) alloc_memory(sizeof(user_t));
    if (!user) {
        return NULL;
    }
    return user;
}

void dinit_user(user_t* user) {
    if (!user) {
        return;
    }
    if (user->login) {
        free(user->login);
        user->login = NULL;
    }
    if (user->password) {
        free(user->password);
        user->password = NULL;
    }
    if (user->ip) {
        free(user->ip);
        user->ip = NULL;
    }
    if (user->mac) {
        free(user->mac);
        user->mac = NULL;
    }
    free(user);
    user = NULL;
}

bool get_user_by_login(const uint8_t *login, user_t* user) {
    sqlite3_stmt* stmt = prepare_statement("SELECT * FROM users WHERE login = ?1;");

    if (!stmt) {
        return false;
    }

    if (!stmt_bind_str(stmt, 1, (char*) login)) {
        sqlite3_finalize(stmt);
        return false;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user->id = (uint32_t) sqlite3_column_int(stmt, 0);
        user->login = copy_str((char*) sqlite3_column_text(stmt, 1));
        user->password = copy_str((char*) sqlite3_column_text(stmt, 2));
        user->ip = copy_str((char*) sqlite3_column_text(stmt, 3));
        user->mac = copy_str((char*) sqlite3_column_text(stmt, 4));

        if (!user->login) {
            sqlite3_finalize(stmt);
            return false;
        }
    }

    sqlite3_finalize(stmt);
    return true;
}