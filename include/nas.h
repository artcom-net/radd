#pragma once

#include <stdint.h>

typedef enum {
    PASSWORD_AUTH,
    IP_AUTH,
    MAC_AUTH
} auth_type_t;


typedef struct {
    uint32_t id;
    char* ip;
    char* secret;
    auth_type_t auth_type;
} nas_t;

nas_t* init_nas();
void dinit_nas(nas_t* nas);
bool get_nas_by_ip(char* nas_ip, nas_t* nas);
const char* const get_auth_type_str(auth_type_t auth_type);
