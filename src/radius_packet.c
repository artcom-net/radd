#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "logger.h"
#include "radius_packet.h"


#define REQ_CODES_ARRAY_SIZE 14
#define ATTR_NAME_ARRAY_SIZE 64
#define ATTR_TYPE_LEN_ARRAY_SIZE 5

#define MAX_TEXT_VALUE_LEN 253
#define NUMBER_VALUE_LEN 4

char* REQUEST_CODES_STR[REQ_CODES_ARRAY_SIZE] = {
    NULL,
    "Access-Request", 
    "Access-Accept", 
    "Access-Reject", 
    "Accounting-Request", 
    "Accounting-Response", 
    "Accounting-Status",
    "Password-Request",
    "Password-Ack",
    "Password-Reject",
    "Accounting-Message",
    "Access-Challenge",
    "Status-Server",
    "Status-Client" 
};

//typedef enum {
//    TEXT,
//    STRING,
//    ADDRESS,
//    UINTEGER,
//    TIME
//} attribute_type_t;

//attribute_meta_t _ATTR_META[] = {
//    {0},
//    {"User-Name", STRING},
//    {"User-Password", STRING},
//    {"CHAP-Password", STRING},
//    {"NAS-IP-Address", ADDRESS},
//    {"NAS-Port", UINTEGER},
//    {"Service-Type", UINTEGER},
//    {"Framed-Protocol", UINTEGER},
//    {"Framed-IP-Address", ADDRESS},
//    {"Framed-IP-Netmask", ADDRESS},
//    {"Framed-Routing", UINTEGER},
//    {"Filter-Id", TEXT},
//    {"Framed-MTU", UINTEGER},
//    {"Framed-Compression", UINTEGER},
//    {"Login-IP-Host", ADDRESS},
//    {"Login-Service", UINTEGER},
//    {"Login-TCP-Port", UINTEGER},
//    {0},
//    {"Reply-Message", TEXT},
//    {"Callback-Number", STRING},
//    {"Callback-Id", STRING},
//    {0},
//    {"Framed-Route", TEXT},
//    {"Framed-IPX-Network", UINTEGER},
//    {"State", STRING},
//    {"Class", STRING},
//    {"Vendor-Specific", STRING},
//    {"Session-Timeout", UINTEGER},
//    {"Idle-Timeout", UINTEGER},
//    {"Termination-Action", UINTEGER},
//    {"Called-Station-Id", STRING},
//    {"Calling-Station-Id", STRING},
//    {"NAS-Identifier", STRING},
//    {"Proxy-State", STRING},
//    {"Login-LAT-Service", STRING},
//    {"Login-LAT-Node", STRING},
//    {"Login-LAT-Group", STRING},
//    {"Framed-Appletalk-Link", UINTEGER},
//    {"Framed-Appletalk-Network", UINTEGER},
//    {"Framed-Appletalk-Zone", STRING},
//    // Accounting.
//    {"Acct-Status-Type", UINTEGER},
//    {"Acct-Delay-Time", UINTEGER},
//    {"Acct-Input-Octets", UINTEGER},
//    {"Acct-Output-Octets", UINTEGER},
//    {"Acct-Session-Id", STRING},
//    {"Acct-Authentic", UINTEGER},
//    {"Acct-Session-Time", UINTEGER},
//    {"Acct-Input-Packets", UINTEGER},
//    {"Acct-Output-Packets", UINTEGER},
//    {"Acct-Terminate-Cause", UINTEGER},
//    {"Acct-Multi-Session-id", STRING},
//    {"Acct-Link-Count", UINTEGER},
//    //
//    {"CHAP-Challenge", STRING},
//    {"NAS-Port-Type", UINTEGER},
//    {"Port-Limit", UINTEGER},
//    {"Login-LAT-Port", STRING}
//};


radius_packet_t* init_radius_packet() {
    radius_packet_t* packet = (radius_packet_t*) alloc_memory(sizeof(radius_packet_t));
    if (!packet) {
        return NULL;
    }
    return packet;
}

attribute_t* attribute_init() {
    attribute_t* attr = (attribute_t*) malloc(sizeof(attribute_t));
    attr->code = 0;
    attr->length = 0;
    attr->value = NULL;
    return attr;
}

attribute_t* get_attr_from_pkt(radius_packet_t* packet, uint8_t code) {
    for (uint8_t i = 0; i < packet->attr_count; ++i) {
        if (packet->attr[i].code == code) {
            return &(packet->attr[i]);
        }
    }
    return NULL;
}

char* get_request_type_str(uint8_t code) {
    if (code > REQ_CODES_ARRAY_SIZE - 1) {
        return NULL;
    }
    return REQUEST_CODES_STR[code];
}

//char* get_attr_name(uint8_t code) {
//    if (code > ATTR_NAME_ARRAY_SIZE - 1) {
//        return NULL;
//    }
//    return ATTR_STR[code];
//}

//attribute_meta_t* get_attr_meta(uint8_t code) {
//    if (code > ATTR_NAME_ARRAY_SIZE - 1) {
//        log_warning("Incorrect attribute code: %u\n", code);
//        return NULL;
//    }
//    attribute_meta_t* attr = &(_ATTR_META[code]);
//
//    if (!attr->name) {
//        log_warning("Attribute with code %u does not exists\n", code);
//        return NULL;
//    }
//
//    return attr;
//}


void log_packet_data(radius_packet_t* packet) {
    log_debug("CODE: %u (%s); IDENTIFIER: %u; LENGTH: %u; AUTHENTICATOR: ",
            packet->code, get_request_type_str(packet->code), packet->identifier, packet->length);

    for (int i = 0; i < PACKET__AUTHENTICATOR_LEN; ++i) {
        log_chunk("%02X", packet->authenticator[i]);
    }

    log_chunk("\n");

    if (packet->attr_count) {
        for (int i = 0; i < packet->attr_count; ++i) {
            attribute_t attr = packet->attr[i];

            if (!attr.code) {
                continue;
            }

            uint8_t attr_payload_len = 0;

            if (attr.vendor_code) {
                attr_payload_len = PACKET__ATTR_VSA_PAYLOAD_LEN(attr);
                log_debug("ATTRIBUTE: code: %u; name: %s; length: %u; vendor_id: %u; vendor_code: %u; vendor_length: %u; value: ",
                        attr.code, attr.meta->name, attr.length, attr.vendor_id, attr.vendor_code, attr.vendor_length);
            }
            else {
                attr_payload_len = PACKET__ATTR_PAYLOAD_LEN(attr);
                log_debug("ATTRIBUTE: code: %u; name: %s; length: %u; value: ", attr.code, attr.meta->name, attr.length);
            }

            switch (attr.meta->type) {
                case TEXT:
                case STRING:
                    for (int j = 0; j < attr_payload_len; ++j) {
                        log_chunk("%c", attr.value[j]);
                    }
                    log_chunk("\n");
                    break;
                case ADDRESS:
                    log_chunk("%u.%u.%u.%u\n", attr.value[0], attr.value[1], attr.value[2], attr.value[3]);
                    break;
                case UINTEGER:
                case TIME:
                    log_chunk("%u\n", attr.value[0] << 24 | attr.value[1] << 16 | attr.value[2] << 8 | attr.value[3]);
                    break;
                default:
                    continue;
            }
        }
    }
}

// TODO: Separate on two functions: _parse_header and _parse_attrs.
bool parse_radius_packet(const char* data, ssize_t data_len, radius_packet_t* packet) {
    if (data_len < PACKET__MIN_PKT_LEN) {
        log_error("Packet is malformed, payload length = %zd\n", data_len);
        return false;
    }
    // Code.
    packet->code = (uint8_t) data[PACKET__CODE_OFFSET];

    switch (packet->code) {
        case PKT_TYPE__ACCESS_REQUEST:
            break;
        case PKT_TYPE__ACCOUNTING_REQUEST:
            break;
        default:
            log_warning("Unknown or unsupported request type: %u.\n", packet->code);
            return false;
    }

    // Identifier.
    packet->identifier = (uint8_t) data[PACKET__IDENTIFIER_OFFSET];

    // Length.
    packet->length = (uint8_t) (data[PACKET__LENGTH_OFFSET] << 8) | (uint8_t) data[PACKET__LENGTH_OFFSET + 1];

    // Authenticator.
    const char* data_ptr = &(data[PACKET__AUTHENTICATOR_OFFSET]);
    memcpy(packet->authenticator, data_ptr, sizeof(uint8_t) * PACKET__AUTHENTICATOR_LEN);

    // Calculates attributes count.
    uint8_t attr_len = 0;
    uint16_t attr_len_index = PACKET__ATTRS_OFFSET + 1;

    while (attr_len_index < data_len) {
        attr_len = (uint8_t) data[attr_len_index];

        if (attr_len < PACKET__MIN_ATTR_LEN) {
            log_error("Error parsing attributes, incorrect attr length: %u\n", attr_len);
            return false;
        }

        attr_len_index += attr_len;
        ++packet->attr_count;
    }

    if (--attr_len_index != data_len) {
        log_error("Error parsing attributes, packet length is malformed: %zd\n", data_len);
        return false;
    }

    // Parse attributes.
    packet->attr = (attribute_t*) alloc_memory(sizeof(attribute_t) * packet->attr_count);

    if (!packet->attr) {
        return false;
    }

    data_ptr = &(data[PACKET__ATTRS_OFFSET]);

    for (size_t i = 0; i < packet->attr_count; ++i) {
        attribute_t* attr_ptr = &(packet->attr[i]);
        attr_ptr->code = (uint8_t) *data_ptr++;
        attr_ptr->meta = get_dict_item(attr_ptr->code);

        if (!attr_ptr->meta) {
            log_warning("Attribute with code = %u, not found\n", attr_ptr->code);
            memset(attr_ptr, 0, sizeof(attribute_t));
            continue;
        }

        attr_ptr->length = (uint8_t) *data_ptr++;
        uint8_t attr_payload_len = 0;

        if (attr_ptr->code == ATTR_CODE__VENDOR_SPECIFIC) {

            if (attr_ptr->length < PACKET__MIN_VSA_LEN) {
                log_error("Error parsing VSA, incorrect length: %u\n", attr_ptr->length);
                // TODO: Change this on --i.
                memset(attr_ptr, 0, sizeof(attribute_t));
                continue;
            }
            /*
                https://tools.ietf.org/html/rfc2865#page-47
                Vendor-Id
                    The high-order octet is 0 and the low-order 3 octets are the SMI
                    Network Management Private Enterprise Code of the Vendor.
            */
            attr_ptr->vendor_id = (uint32_t) *data_ptr++ << 24 | *data_ptr++ << 16 | *data_ptr++ << 8 | *data_ptr++;
            attr_ptr->vendor_code = (uint8_t) *data_ptr++;
            uint8_t vendor_length = (uint8_t) *data_ptr++;

            if (vendor_length < PACKET__MIN_ATTR_LEN) {
                log_error("Error parsing VSA, incorrect length: %u\n", vendor_length);
                memset(attr_ptr, 0, sizeof(attribute_t));
                continue;
            }

            attr_ptr->vendor_length = vendor_length;
            attr_payload_len = PACKET__ATTR_VSA_PAYLOAD_LEN((*attr_ptr));
        }
        else {
            attr_payload_len = PACKET__ATTR_PAYLOAD_LEN((*attr_ptr));
        }

        bool is_valid_len = true;
        bool is_text = false;
        size_t alloc_bytes = attr_payload_len;

        if (attr_ptr->meta->type == TEXT || attr_ptr->meta->type == STRING) {
            if (attr_payload_len > MAX_TEXT_VALUE_LEN) {
                is_valid_len = false;
            }
            else {
                is_text = true;
                // Additional byte to NULL-terminator.
                ++alloc_bytes;
            }
        }
        else {
            if (attr_payload_len != NUMBER_VALUE_LEN) {
                is_valid_len = false;
            }
        }

        if (!is_valid_len) {
            log_warning("%s attribute value exceed max: %u\n", attr_ptr->meta->name, attr_payload_len);
            memset(attr_ptr, 0, sizeof(attribute_t));
            // Maybe return?
            continue;
        }

        attr_ptr->value = (uint8_t*) alloc_memory(sizeof(uint8_t) * alloc_bytes);

        if (!attr_ptr->value) {
            dinit_radius_packet(packet);
            return false;
        }

        memcpy(attr_ptr->value, data_ptr, sizeof(uint8_t) * attr_payload_len);

        if (is_text) {
            attr_ptr->value[attr_payload_len] = NULL_TERM;
        }

        data_ptr += attr_payload_len;
    }
    
    return true;
}

void dinit_radius_packet(radius_packet_t* packet) {
    if (!packet) {
        return;
    }

    if (packet->attr) {
        for (int i = 0; i < packet->attr_count; ++i) {
            attribute_t* attr = &(packet->attr[i]);

            if (attr && attr->value) {
                free(attr->value);
                attr->value = NULL;
                attr = NULL;
            }
        }

        free(packet->attr);
        packet->attr = NULL;
    }

    free(packet);
    packet = NULL;
}
