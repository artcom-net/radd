#pragma once

#include <stdbool.h>
#include <stdint.h>


typedef struct {
    uint32_t id;
    char* login;
    char* password;
    char* ip;
    char* mac;
} user_t;

user_t* init_user();
void dinit_user(user_t* user);
bool get_user_by_login(const uint8_t *login, user_t* user);