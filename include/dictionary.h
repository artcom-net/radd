#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    TEXT,
    STRING,
    ADDRESS,
    UINTEGER,
    TIME
} attribute_type_t;

typedef struct {
    uint32_t id;
    uint8_t code;
    attribute_type_t type;
    char* name;
} dict_item_t;


bool init_dictionary();
void dinit_dictionary();
dict_item_t* get_dict_item(uint8_t code);
