#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "common.h"
#include "logger.h"

#define DATE_TIME_BUFFER_SIZE 20
#define DATE_TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define LOG_META_FMT "%s %s %s:%u "

const char* const _LOG_LEVELS_STR[] = {"UNDEFINED", "DEBUG", "INFO", "WARNING", "ERROR", "FATAL"};

typedef struct {
    FILE* fd;
    log_level_t level;
    bool is_init;
} logger_t;

logger_t _logger = {0};

bool _is_valid_log_level(log_level_t level) {
    switch (level) {
        case LL_DEBUG:
        case LL_INFO:
        case LL_WARNING:
        case LL_ERROR:
        case LL_FATAL:
            return true;
        default:
            return false;
    }
}

const char* const get_log_level_str(log_level_t level) {
    if (!_is_valid_log_level(level)) {
        return NULL;
    }
    return _LOG_LEVELS_STR[level];
}

bool init_logger(char* file_path, log_level_t level) {
    if (!_is_valid_log_level(level)) {
        log_fatal("Invalid log level: %u\n", level);
        return false;
    }

    errno = 0;
    FILE* log_fd = fopen(file_path, "a+");

    if (!log_fd) {
        fprintf(stderr, "%s: %s\n", strerror(errno), file_path);
        return false;
    }

    // _logger.fd = log_fd;
    _logger.fd = stdout;
    _logger.level = level;
    _logger.is_init = true;
    return true;
}

void dinit_logger() {
    if (_logger.fd) {
        fclose(_logger.fd);
        _logger.fd = NULL;
    }
    _logger.is_init = false;
}

void log_chunk(const char* fmt, ...) {
    va_list arg_ptr;
    va_start(arg_ptr, fmt);
    vfprintf(_logger.fd, fmt, arg_ptr);
    va_end(arg_ptr);
    fflush(_logger.fd);
}

// add is_init for fprintf to stderr.
void _log(log_level_t level, const char* file_name, uint32_t line, const char* fmt, ...) {

    if (!_logger.is_init) {
        _logger.fd = stderr;
        _logger.level = LL_WARNING;
    }

    if (level < _logger.level) {
        return;
    }

    time_t curr_time = time(NULL);
    struct tm* local_time = localtime(&curr_time);
    char date_time_buffer[DATE_TIME_BUFFER_SIZE];
    size_t write_bytes = strftime(date_time_buffer, sizeof(date_time_buffer), DATE_TIME_FORMAT, local_time);
    date_time_buffer[write_bytes] = NULL_TERM;
    fprintf(_logger.fd, LOG_META_FMT, date_time_buffer, get_log_level_str(level), file_name, line);

    va_list arg_ptr;
    va_start(arg_ptr, fmt);
    vfprintf(_logger.fd, fmt, arg_ptr);
    va_end(arg_ptr);

    fflush(_logger.fd);
}