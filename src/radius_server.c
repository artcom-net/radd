#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/md5.h>  /* libssl-dev */

#include "db.h"
#include "logger.h"
#include "nas.h"
#include "radius_packet.h"
#include "radius_server.h"
#include "user.h"


typedef enum{
    NONE,
    AUTH_REQUEST,
    ACCT_REQUEST
} request_type_t;

typedef struct {
    int sock;
    request_type_t req_type;
    nas_t* nas;
    radius_packet_t* req_packet;
    radius_packet_t* res_packet;
} request_context_t;

void _dinit_req_context(request_context_t* context) {
    if (!context) {
        return;
    }
    dinit_nas(context->nas);
    dinit_radius_packet(context->req_packet);
    dinit_radius_packet(context->res_packet);
    free(context);

    context->nas = NULL;
    context->req_packet = NULL;
    context->res_packet = NULL;
    context = NULL;
}

request_context_t* _init_req_context() {
    request_context_t* context = (request_context_t*) alloc_memory(sizeof(request_context_t));

    if (!context) {
        return NULL;
    }

    context->nas = (nas_t*) alloc_memory(sizeof(nas_t));
    context->req_packet = (radius_packet_t*) alloc_memory(sizeof(radius_packet_t));
    context->res_packet = (radius_packet_t*) alloc_memory(sizeof(radius_packet_t));

    if (!context->nas || !context->req_packet || !context->res_packet) {
        _dinit_req_context(context);
        return NULL;
    }

    return context;
}

int _bind_socket(const char* ip_addr, uint16_t port)
{
    int sock = 0;
    struct sockaddr_in sock_addr = {0};
    errno = 0;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_fatal("socket: %s\n", strerror(errno));
        return -1;
    }

    int on_flag = 1;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on_flag, sizeof(on_flag)) == -1) {
        log_fatal("setsockopt: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = inet_addr(ip_addr);
    sock_addr.sin_port = htons(port);

    if ((bind(sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr))) == -1) {
        log_fatal("bind: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

bool _is_valid_password(char* user_pass, const uint8_t* user_pass_hash, uint8_t* authenticator, char* secret) {
    // https://tools.ietf.org/html/rfc2865#page-27
    // TODO: Password may be exceed than 16 bytes.
    uint8_t pass_padded[MD5_DIGEST_LENGTH];
    size_t pass_len = strlen(user_pass);

    for (uint8_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        if (i >= pass_len) {
            pass_padded[i] = 0;
            continue;
        }
        pass_padded[i] = (uint8_t) user_pass[i];
    }

    size_t secret_len = strlen(secret);
    size_t ss_ra_len = secret_len + PACKET__AUTHENTICATOR_LEN;
    uint8_t ss_ra[ss_ra_len];
    memcpy(ss_ra, secret, sizeof(uint8_t) * secret_len);
    memcpy(&(ss_ra[secret_len]), authenticator, sizeof(uint8_t) * PACKET__AUTHENTICATOR_LEN);

    uint8_t ss_ra_hash[MD5_DIGEST_LENGTH];
    MD5(ss_ra, ss_ra_len, ss_ra_hash);

    uint16_t _user_pass_hash[MD5_DIGEST_LENGTH];

    for (uint8_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        _user_pass_hash[i] = pass_padded[i] ^ ss_ra_hash[i];
    }

    for (uint8_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        if (_user_pass_hash[i] != (uint8_t) user_pass_hash[i]) {
            return false;
        }
    }

    return true;
}

void _make_response_authenticator(const uint8_t *request_auth, radius_packet_t *response_pkt, const char *secret) {
    uint8_t fields_stream[response_pkt->length + strlen(secret)];
    fields_stream[PACKET__CODE_OFFSET] = response_pkt->code;
    fields_stream[PACKET__IDENTIFIER_OFFSET] = response_pkt->identifier;
    fields_stream[PACKET__LENGTH_OFFSET] = (uint8_t) ((response_pkt->length & 0xFF00) >> 8);
    fields_stream[PACKET__LENGTH_OFFSET + 1] = (uint8_t) (response_pkt->length & 0x00FF);
    memcpy(&(fields_stream[PACKET__AUTHENTICATOR_OFFSET]), request_auth, sizeof(uint8_t) * PACKET__AUTHENTICATOR_LEN);

    uint8_t attr_offset = PACKET__HEADER_LEN;

    for (int i = 0; i < response_pkt->attr_count; ++i) {
        fields_stream[attr_offset++] = response_pkt->attr[i].code;
        fields_stream[attr_offset++] = response_pkt->attr[i].length;
        memcpy(&(fields_stream[attr_offset]), response_pkt->attr[i].value,
                sizeof(uint8_t) * PACKET__ATTR_PAYLOAD_LEN(response_pkt->attr[i]));
        attr_offset += PACKET__ATTR_PAYLOAD_LEN(response_pkt->attr[i]);
    }

    memcpy(&(fields_stream[response_pkt->length]), secret, sizeof(uint8_t) * strlen(secret));
    uint8_t response_auth[MD5_DIGEST_LENGTH];
    MD5(fields_stream, response_pkt->length + strlen(secret), response_auth);
    memcpy(response_pkt->authenticator, response_auth, sizeof(uint8_t) * PACKET__AUTHENTICATOR_LEN);
}

int32_t _auth_handle(radius_packet_t* request_packet, nas_t* nas) {
    if (request_packet->code != PKT_TYPE__ACCESS_REQUEST) {
        log_warning("Incorrect request type: %u\n", request_packet->code);
        return -1;
    }

    attribute_t* user_name_attr = get_attr_from_pkt(request_packet, ATTR_CODE__USER_NAME);

    if (!user_name_attr) {
        log_warning("User-Name attribute was not received.\n");
        return 0;
    }

    if (!get_attr_from_pkt(request_packet, ATTR_CODE__NAS_IP_ADDRESS) && !get_attr_from_pkt(request_packet, ATTR_CODE__NAS_IDENTIFIER)) {
        log_warning("NAS-IP-Address and NAS-Identifier was not received.\n");
        return 0;
    }

    user_t user = {0};

    if (!get_user_by_login(user_name_attr->value, &user)) {
        return 0;
    }

    if (user.id == 0) {
        log_warning("User not found: %s\n", user_name_attr->value);
        return 0;
    }

    attribute_t* user_pass_attr = NULL;
    attribute_t* framed_ip_address = NULL;
    attribute_t* calling_station_id = NULL;

    switch (nas->auth_type) {
        case PASSWORD_AUTH:
            if (!user.password) {
                log_error("User %s dont have a password\n", user.login);
                return 0;
            }

            user_pass_attr = get_attr_from_pkt(request_packet, ATTR_CODE__USER_PASSWORD);

            if (!user_pass_attr) {
                log_warning("User-Password attribute was not received. Skipped..\n");
                return 0;
            }

            if (!_is_valid_password(user.password, user_pass_attr->value, request_packet->authenticator, nas->secret)) {
                log_warning("Password is incorrect for login = %s. Skipped..\n", user.login);
                return 0;
            }
            break;

        case IP_AUTH:
            if (!user.ip) {
                log_error("User %s dont have a IP\n", user.login);
                return 0;
            }

            framed_ip_address = get_attr_from_pkt(request_packet, ATTR_CODE__FRAMED_IP_ADDRESS);

            if (!framed_ip_address) {
                log_warning("Framed-IP-Address attribute was not received. Skipped..\n");
                return 0;
            }

            char ip[MAX_IP_LEN + 1] = {0};
            snprintf(ip, MAX_IP_LEN, "%u.%u.%u.%u", framed_ip_address->value[0], framed_ip_address->value[1],
                    framed_ip_address->value[2], framed_ip_address->value[3]);

            if (strcmp(ip, user.ip) != 0) {
                log_warning("IP address mismatch: %s != %s\n", ip, user.ip);
                return 0;
            }
            break;

        case MAC_AUTH:
            if (!user.mac) {
                log_error("User %s dont have a MAC\n", user.login);
                return 0;
            }

            calling_station_id = get_attr_from_pkt(request_packet, ATTR_CODE__CALLING_STATION_ID);

            if (!calling_station_id) {
                log_warning("Calling-Station-Id attribute was not received. Skipped..\n");
                return 0;
            }

            if (strcmp((char*) calling_station_id->value, user.mac) != 0) {
                log_warning("MAC address mismatch: %s != %s\n", calling_station_id->value, user.mac);
                return 0;
            }
            break;

        default:
            break;
    }

    return user.id;
}

// TODO: Move it to radius_packet.c
void _packet_to_stream(radius_packet_t *packet, uint8_t *octets_stream) {
    octets_stream[PACKET__CODE_OFFSET] = packet->code;
    octets_stream[PACKET__IDENTIFIER_OFFSET] = packet->identifier;
    octets_stream[PACKET__LENGTH_OFFSET] = (uint8_t) ((packet->length & 0xFF00) >> 8);
    octets_stream[PACKET__LENGTH_OFFSET + 1] = (uint8_t) (packet->length & 0x00FF);
    memcpy(&(octets_stream[PACKET__AUTHENTICATOR_OFFSET]), packet->authenticator, sizeof(uint8_t) * PACKET__AUTHENTICATOR_LEN);
    if (packet->attr_count) {
        uint8_t attr_offset = PACKET__HEADER_LEN;
        for (int i = 0; i < packet->attr_count; ++i) {
            // Maybe get attr.length and to call memcpy?
            octets_stream[attr_offset++] = packet->attr[i].code;
            octets_stream[attr_offset++] = packet->attr[i].length;
            memcpy(&(octets_stream[attr_offset]), packet->attr[i].value, sizeof(uint8_t) * PACKET__ATTR_PAYLOAD_LEN(packet->attr[i]));

            attr_offset += PACKET__ATTR_PAYLOAD_LEN(packet->attr[i]);
        }
    }
}


bool _get_reply_attrs_count(int32_t user_id, uint8_t reply_code, uint8_t *count) {
    sqlite3_stmt* stmt = prepare_statement(
            "SELECT COUNT(*) FROM reply_attrs WHERE user_id = ?1 AND reply_code = ?2;");

    if (!stmt || !stmt_bind_int(stmt, 1, user_id) || !stmt_bind_int(stmt, 2, reply_code)) {
        return false;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *count = (uint8_t) sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return true;
}

bool _get_reply_attrs(int32_t user_id, radius_packet_t *packet) {
    uint8_t attrs_count = 0;

    if (!_get_reply_attrs_count(user_id, packet->code, &attrs_count)) {
        return false;
    }

    if (attrs_count == 0) {
        return true;
    }

    sqlite3_stmt* stmt = prepare_statement(
            "SELECT d.code, r.attr_value FROM reply_attrs r JOIN dictionary d ON r.attr_id = d.id "
            "WHERE r.user_id = ?1 AND r.reply_code = ?2 LIMIT ?3;");

    if (!stmt || !stmt_bind_int(stmt, 1, user_id) || !stmt_bind_int(stmt, 2, packet->code) || !stmt_bind_int(stmt, 3, attrs_count)) {
        return false;
    }

    packet->attr = (attribute_t*) alloc_memory(sizeof(attribute_t) * attrs_count);

    if (!packet->attr) {
        sqlite3_finalize(stmt);
        return false;
    }

    for (int i = 0; sqlite3_step(stmt) == SQLITE_ROW; ++i) {
        uint8_t attr_code = (uint8_t) sqlite3_column_int(stmt, 0);
        dict_item_t* dict_item = get_dict_item(attr_code);

        if (!dict_item) {
            log_warning("Unknown attribute with code = %u\n", attr_code);
            --i;
            continue;
        }

        attribute_t* attr = &(packet->attr[i]);
        attr->code = attr_code;
        attr->meta = dict_item;

        const char* str_value = (char*) sqlite3_column_text(stmt, 1);
        size_t str_value_len = strlen(str_value);

        if (str_value_len == 0) {
            log_warning("Attribute %s has invalid length: %lu\n", attr->meta->name, str_value_len);
            --i;
            continue;
        }

        switch (attr->meta->type) {
            case TEXT:
            case STRING:
                attr->value = (uint8_t*) copy_str(str_value);

                if (!attr->value) {
                    --i;
                    continue;
                }

                attr->length = (uint8_t) (str_value_len + PACKET__ATTR_HEADER_LEN);
                break;

            case ADDRESS:
                attr->value = (uint8_t*) alloc_memory(sizeof(uint32_t));

                if (!attr->value) {
                    --i;
                    continue;
                }


                if (inet_pton(AF_INET, str_value, attr->value) != 1) {
                    log_error("IPv4 address is incorrect\n");
                    --i;
                    continue;
                }

                attr->length = (uint8_t) (sizeof(uint32_t) + PACKET__ATTR_HEADER_LEN);
                break;

            case UINTEGER:
            case TIME:
                attr->value = (uint8_t*) alloc_memory(sizeof(uint32_t));

                if (!attr->value) {
                    --i;
                    continue;
                }

                uint32_t num = 0;

                if (!str_to_uint32((char*) str_value, &num)) {
                    log_error("Failed convertion: %u\n", num);
                    --i;
                    continue;
                }

                attr->value[0] = (uint8_t) (num >> 24);
                attr->value[1] = (uint8_t) (num >> 16);
                attr->value[2] = (uint8_t) (num >> 8);
                attr->value[3] = (uint8_t) num;

                attr->length = (uint8_t) (sizeof(uint32_t) + PACKET__ATTR_HEADER_LEN);
                break;
        }

        ++packet->attr_count;
        packet->length += attr->length;
    }

    sqlite3_finalize(stmt);
    return true;
}

void _handle_request(request_context_t* context) {
    int sock = context->sock;
    char buffer[PACKET__MAX_PKT_LEN] = {0};
    ssize_t read_bytes = 0;
    struct sockaddr_in remote_addr = {0};
    socklen_t addr_len = sizeof(remote_addr);
    errno = 0;

    if ((read_bytes = recvfrom(sock, buffer, PACKET__MAX_PKT_LEN, 0, (struct sockaddr *) &remote_addr, &addr_len)) == -1) {
        log_error("recvfrom: %s\n", strerror(errno));
        return;
    }

    if (read_bytes == 0) {
        log_debug("Packet payload is empty\n");
        return;
    }

    char* nas_ip = inet_ntoa(remote_addr.sin_addr);
    nas_t* nas = context->nas;
    radius_packet_t* req_packet = context->req_packet;
    radius_packet_t* res_packet = context->res_packet;

    if (!get_nas_by_ip(nas_ip, nas)) {
        return;
    }

    if (nas->id == 0) {
        log_debug("Request from unknown NAS, IP = %s\n", nas_ip);
        return;
    }

    if (!parse_radius_packet(buffer, read_bytes, req_packet)) {
        return;
    }

    log_packet_data(req_packet);
    res_packet->length = PACKET__HEADER_LEN;
    int32_t user_id = 0;

    switch (context->req_type) {
        case AUTH_REQUEST:
            if ((user_id = _auth_handle(req_packet, nas)) == -1) {
                return;
            }
            res_packet->code = user_id ? PKT_TYPE__ACCESS_ACCEPT : PKT_TYPE__ACCESS_REJECT;
            break;
        case ACCT_REQUEST:
            break;
        default:
            break;
    }

    if (user_id && !_get_reply_attrs(user_id, res_packet)) {
        return;
    }

    res_packet->identifier = req_packet->identifier;
    _make_response_authenticator(req_packet->authenticator, res_packet, nas->secret);
    uint8_t octet_stream[res_packet->length];
    _packet_to_stream(res_packet, octet_stream);

    errno = 0;
    ssize_t sent_bytes = sendto(sock, octet_stream, res_packet->length, 0, (struct sockaddr*)
            &remote_addr, sizeof(remote_addr));

    if (sent_bytes == -1) {
        log_fatal("sendto: %s\n", strerror(errno));
        return;
    }

    log_debug("Sent bytes: %zd\n", sent_bytes);
}


bool start_radius_server(char* listen, uint16_t auth_port, uint16_t acct_port) {
    int auth_sock = 0;
    int acct_sock = 0;

    if ((auth_sock = _bind_socket(listen, auth_port)) == -1) {
        return false;
    }

    if ((acct_sock = _bind_socket(listen, acct_port)) == -1) {
        close(auth_sock);
        return false;
    }

    fd_set read_socks;
    FD_ZERO(&read_socks);
    FD_SET(auth_sock, &read_socks);
    FD_SET(acct_sock, &read_socks);

    int max_sock_id = (acct_sock > auth_sock ? acct_sock : auth_sock) + 1;

    log_info("RADIUS server started listen: %s:%u; %s:%u\n", listen, auth_port, listen, acct_port);

    while (true) {
        errno = 0;
        if (select(max_sock_id, &read_socks, NULL, NULL, 0) == -1) {
            log_error("select: %s", strerror(errno));
            continue;
        }

        request_context_t* req_context = _init_req_context();

        if (!req_context) {
            FD_CLR(auth_sock, &read_socks);
            FD_CLR(acct_sock, &read_socks);
            close(auth_sock);
            close(acct_sock);
            return false;
        }

        if (FD_ISSET(auth_sock, &read_socks)) {
            req_context->sock = auth_sock;
            req_context->req_type = AUTH_REQUEST;
        }

        else if (FD_ISSET(acct_sock, &read_socks)) {
            req_context->sock = acct_sock;
            req_context->req_type = ACCT_REQUEST;
        }

        _handle_request(req_context);
        _dinit_req_context(req_context);
    }
}
