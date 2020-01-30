#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "db.h"
#include "logger.h"


sqlite3* _db = NULL;


bool _is_valid_result(int result, sqlite3_stmt* stmt) {
    if (result != SQLITE_OK) {
        log_error("%s\n", sqlite3_errmsg(_db));
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return false;
    }
    return true;
}

void dinit_db() {
    if (_db) {
        sqlite3_close_v2(_db);
    }
    _db = NULL;
}

bool init_db(const char* db_name) {
    int result = sqlite3_open_v2(db_name, &_db, SQLITE_OPEN_READWRITE, NULL);
    return _is_valid_result(result, NULL);

//    sqlite3* _db;
//    sqlite3_stmt* stmt;
//
//    int res = sqlite3_open_v2(db_name, &_db, SQLITE_OPEN_READWRITE, NULL);
//
//    if (res != SQLITE_OK) {
//        printf("Failed to open database: %s\n", db_name);
//        return;
//    }
//
//    res = sqlite3_prepare_v2(_db, "SELECT * FROM users", -1, &stmt, NULL);
//
//    if (res != SQLITE_OK) {
//        printf("Error: sqlite3_prepare_v2\n");
//        return;
//    }
//
//    while (sqlite3_step(stmt) != SQLITE_DONE) {
//        int column_count = sqlite3_column_count(stmt);
//        int int_val;
//        const char* char_val;
//
//        for (int column_index = 0; column_index < column_count; ++column_index) {
//            switch (sqlite3_column_type(stmt, column_index)) {
//                case SQLITE_INTEGER:
//                    int_val = sqlite3_column_int(stmt, column_index);
//                    printf("COLUMN: %d; VAL: %d\n", column_index, int_val);
//                    break;
//                case SQLITE_TEXT:
//                    char_val = sqlite3_column_text(stmt, column_index);
//                    printf("COLUMN: %d; VAL: %s\n", column_index, char_val);
//                    break;
//            }
//        }
//    }
//
//    res = sqlite3_finalize(stmt);
}

sqlite3_stmt* prepare_statement(const char* query) {
    sqlite3_stmt* stmt;

    int result = sqlite3_prepare_v2(_db, query, -1, &stmt, NULL);

    if (!_is_valid_result(result, NULL)) {
        return NULL;
    }

    return stmt;

}

bool stmt_bind_int(sqlite3_stmt* stmt, uint8_t index, int32_t val) {
    int result = sqlite3_bind_int(stmt, index, val);
    return _is_valid_result(result, stmt);
}

bool stmt_bind_str(sqlite3_stmt* stmt, uint8_t index, char* val) {
    int result = sqlite3_bind_text(stmt, index, val, (int) strlen(val), SQLITE_STATIC);
    return _is_valid_result(result, stmt);
}
