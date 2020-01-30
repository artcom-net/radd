#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>


#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_debug(...) _log(LL_DEBUG, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_info(...) _log(LL_INFO, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_warning(...) _log(LL_WARNING, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_error(...) _log(LL_ERROR, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_fatal(...) _log(LL_FATAL, __FILENAME__, __LINE__, __VA_ARGS__)

typedef enum {
    LL_UNDEFINED,
    LL_DEBUG,
    LL_INFO,
    LL_WARNING,
    LL_ERROR,
    LL_FATAL
} log_level_t;


bool init_logger(char* file_path, log_level_t level);
void dinit_logger();
void log_chunk(const char* fmt, ...);
const char* const get_log_level_str(log_level_t level);
void _log(log_level_t level, const char* file_name, uint32_t line, const char* fmt, ...);
