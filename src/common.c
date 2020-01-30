#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "logger.h"

long _str_to_uint(const char* str, const uint32_t max_val) {
    char* end_ptr = NULL;
    errno = 0;
    long val = strtol(str, &end_ptr, 10);
    if (errno == ERANGE || val < 0 || val > max_val || end_ptr == str || *end_ptr != '\0') {
        // TODO: errno may be 0.
        log_fatal("strtol: %s\n", strerror(errno));
        return -1;
    }
    return val;
}

bool str_to_uint8(const char* str, uint8_t* val) {
    long tmp;
    if ((tmp = _str_to_uint(str, UINT8_MAX)) != -1) {
        *val = (uint8_t) tmp;
        return true;
    }
    return false;
}

bool str_to_uint16(char* str, uint16_t* val) {
    long tmp;
    if ((tmp = _str_to_uint(str, UINT16_MAX)) != -1) {
        *val = (uint16_t) tmp;
        return true;
    }
    return false;
}

bool str_to_uint32(char* str, uint32_t* val) {
    long tmp;
    if ((tmp = _str_to_uint(str, UINT32_MAX)) != -1) {
        *val = (uint32_t) tmp;
        return true;
    }
    return false;
}

void* alloc_memory(size_t size) {
    errno = 0;
    void* ptr = malloc(size);
    if (!ptr) {
        log_fatal("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

char* copy_str(const char* str) {
    if (!str) {
        return NULL;
    }

    size_t str_len = strlen(str);
    char* ptr = (char*) alloc_memory(str_len + 1);

    if (!ptr) {
        return NULL;
    }

    strncpy(ptr, str, str_len);
    ptr[str_len] = NULL_TERM;
    return ptr;
}
