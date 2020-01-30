#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/limits.h>

#define NULL_TERM '\0'
#define NEW_LINE '\n'

#define MAX_PATH_LEN PATH_MAX - 1

#define MAX_IP_LEN 12
//#define MAX_IP_ARRAY_SIZE MAX_IP_LEN + 1

#define MAX_MAC_LEN 17
//#define MAX_MAC_ARRAY_SIZE MAX_MAC_LEN + 1

bool str_to_uint8(const char* str, uint8_t* val);
bool str_to_uint16(char* str, uint16_t* val);
bool str_to_uint32(char* str, uint32_t* val);
void* alloc_memory(size_t size);
char* copy_str(const char* str);
