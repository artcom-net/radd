#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <sqlite3.h>    // libsqlite3-dev

#include "common.h"



sqlite3_stmt* prepare_statement(const char* query);
bool init_db(const char* db_name);
void dinit_db();
bool stmt_bind_int(sqlite3_stmt *stmt, uint8_t index, int32_t val);
bool stmt_bind_str(sqlite3_stmt* stmt, uint8_t index, char* val);

//bool _is_valid_result(int result, sqlite3_stmt* stmt);
