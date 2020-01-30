#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "db.h"
#include "dictionary.h"
#include "logger.h"


dict_item_t* _dictionary = NULL;
uint8_t _dict_size = 0;


bool _get_dict_items(uint8_t dict_size) {
    sqlite3_stmt* stmt = prepare_statement("SELECT * FROM dictionary LIMIT ?1;");

    if (!stmt) {
        return false;
    }

    if (!stmt_bind_int(stmt, 1, dict_size)) {
        sqlite3_finalize(stmt);
        return false;
    }

    for (int i = 0; sqlite3_step(stmt) == SQLITE_ROW; ++i) {
        dict_item_t* di = &(_dictionary[i]);
        di->id = (uint32_t) sqlite3_column_int(stmt, 0);
        di->code = (uint8_t) sqlite3_column_int(stmt, 1);
        di->type = sqlite3_column_int(stmt, 2);
        di->name = copy_str((char*) sqlite3_column_text(stmt, 3));

        if (!di->name) {
            sqlite3_finalize(stmt);
            return false;
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

bool init_dictionary() {
    uint8_t count = 0;
    sqlite3_stmt* stmt = prepare_statement("SELECT COUNT(*) FROM dictionary;");
    if (!stmt) {
        return false;
    }
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = (uint8_t) sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);

    if (count == 0) {
        log_error("Dictionary items count is null\n");
        return false;
    }

    _dictionary = (dict_item_t*) alloc_memory(sizeof(dict_item_t) * count);

    if (!_dictionary) {
        return false;
    }

    _dict_size = count;

    if(!_get_dict_items(count)) {
        return false;
    }

    return true;
}

void dinit_dictionary() {
    if (!_dictionary) {
        return;
    }
    for (int i = 0; i < _dict_size ; ++i) {
        char* name_ptr = _dictionary[i].name;
        if (name_ptr) {
            free(name_ptr);
            name_ptr = NULL;
        }
    }
    free(_dictionary);
    _dictionary = NULL;
}

dict_item_t* get_dict_item(uint8_t code) {
    for (int i = 0; i < _dict_size; ++i) {
        if (_dictionary[i].code == code) {
            return &(_dictionary[i]);
        }
    }
    return NULL;
}