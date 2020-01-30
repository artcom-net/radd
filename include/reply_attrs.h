#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t code;
    char* value;
} reply_attr_t;

bool get_reply_attrs(uint32_t user_id, uint8_t reply_code, reply_attr_t* reply_attrs);
