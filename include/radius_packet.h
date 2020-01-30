#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dictionary.h"


/* Headers length */
#define PACKET__HEADER_LEN 20
#define PACKET__ATTR_HEADER_LEN 2
#define PACKET__ATTR_VSA_HEADER_LEN 6

/* Fields length */
#define PACKET__CODE_LEN 1
#define PACKET__IDENTIFIER_LEN 1
#define PACKET__LENGTH_LEN 2
#define PACKET__AUTHENTICATOR_LEN 16

/* Fields offset */
#define PACKET__CODE_OFFSET 0
#define PACKET__IDENTIFIER_OFFSET 1
#define PACKET__LENGTH_OFFSET 2
#define PACKET__AUTHENTICATOR_OFFSET 4
#define PACKET__ATTRS_OFFSET PACKET__HEADER_LEN

/* Limits */
#define PACKET__MIN_ATTR_LEN (PACKET__ATTR_HEADER_LEN + 1)
#define PACKET__MIN_VSA_LEN 7
// TODO: Rename this file to packet.h(c).
#define PACKET__MAX_PKT_LEN 4096
#define PACKET__MIN_PKT_LEN (PACKET__HEADER_LEN + PACKET__MIN_ATTR_LEN)

/* Payloads length */
#define PACKET__ATTR_PAYLOAD_LEN(attr) (uint8_t) (attr.length - PACKET__ATTR_HEADER_LEN)
#define PACKET__ATTR_VSA_PAYLOAD_LEN(attr) (uint8_t) (PACKET__ATTR_PAYLOAD_LEN(attr) - PACKET__ATTR_VSA_HEADER_LEN)


typedef enum {
	PKT_TYPE__UNDEFINED,
	PKT_TYPE__ACCESS_REQUEST,
	PKT_TYPE__ACCESS_ACCEPT,
	PKT_TYPE__ACCESS_REJECT,
	PKT_TYPE__ACCOUNTING_REQUEST,
	PKT_TYPE__ACCOUNTING_RESPONSE,
	PKT_TYPE__ACCOUNTING_STATUS,
	PKT_TYPE__PASSWORD_REQUEST,
	PKT_TYPE__PASSWORD_ACK,
	PKT_TYPE__PASSWORD_REJECT,
	PKT_TYPE__ACCOUNTING_MESSAGE,
	PKT_TYPE__ACCESS_CHALLENGE,
	PKT_TYPE__STATUS_SERVER,
	PKT_TYPE__STATUS_CLIENT
} packet_type_t;

typedef enum {
	ATTR_CODE__UNDEFINED,
	ATTR_CODE__USER_NAME,
	ATTR_CODE__USER_PASSWORD,
	ATTR_CODE__CHAP_PASSWORD,
	ATTR_CODE__NAS_IP_ADDRESS,
	ATTR_CODE__NAS_PORT,
	ATTR_CODE__SERVICE_TYPE,
	ATTR_CODE__FRAMED_PROTOCOL,
	ATTR_CODE__FRAMED_IP_ADDRESS,
	ATTR_CODE__FRAMED_IP_NETMASK,
	ATTR_CODE__FRAMED_ROUTING,
	ATTR_CODE__FILTER_ID,
	ATTR_CODE__FRAMED_MTU ,
	ATTR_CODE__FRAMED_COMPRESSION,
	ATTR_CODE__LOGIN_IP_HOST,
	ATTR_CODE__LOGIN_SERVICE,
	ATTR_CODE__LOGIN_TCP_PORT,
	ATTR_CODE__REPLY_MESSAGE = 18,
	ATTR_CODE__CALLBACK_NUMBER,
	ATTR_CODE__CALLBACK_ID,
	ATTR_CODE__FRAMED_ROUTE = 22,
	ATTR_CODE__FRAMED_IPX_NETWORK,
	ATTR_CODE__STATE,
	ATTR_CODE__CLASS,
	ATTR_CODE__VENDOR_SPECIFIC,
	ATTR_CODE__SESSION_TIMEOUT,
	ATTR_CODE__IDLE_TIMEOUT,
	ATTR_CODE__TERMINATION_ACTION,
	ATTR_CODE__CALLED_STATION_ID,
	ATTR_CODE__CALLING_STATION_ID,
	ATTR_CODE__NAS_IDENTIFIER,
	ATTR_CODE__PROXY_STATE,
	ATTR_CODE__LOGIN_LAT_SERVICE,
	ATTR_CODE__LOGIN_LAT_NODE,
	ATTR_CODE__LOGIN_LAT_GROUP,
	ATTR_CODE__FRAMED_APPLETALK_LINK,
	ATTR_CODE__FRAMED_APPLETALK_NETWORK,
	ATTR_CODE__FRAMED_APPLETALK_ZONE,
	// Accounting.
	ATTR_CODE__ACCT_STATUS_TYPE,
	ATTR_CODE__ACCT_DELAY_TIME,
	ATTR_CODE__ACCT_INPUT_OCTETS,
	ATTR_CODE__ACCT_OUTPUT_OCTETS,
	ATTR_CODE__ACCT_SESSION_ID,
	ATTR_CODE__ACCT_AUTHENTIC,
	ATTR_CODE__ACCT_SESSION_TIME,
	ATTR_CODE__ACCT_INPUT_PACKETS,
	ATTR_CODE__ACCT_OUTPUT_PACKETS,
	ATTR_CODE__ACCT_TERMINATE_CAUSE,
	ATTR_CODE__ACCT_MULTI_SESSION_ID,
	ATTR_CODE__ACCT_LINK_COUNT,
	//
	ATTR_CODE__CHAP_CHALLENGE = 60,
	ATTR_CODE__NAS_PORT_TYPE,
	ATTR_CODE__PORT_LIMIT,
	ATTR_CODE__LOGIN_LAT_PORT
} attribute_code_t;

// TODO: Create new struct attribute_vsa_t.
typedef struct {
    attribute_code_t code;
	uint8_t length;
	uint8_t* value;
	dict_item_t* meta;
	uint32_t vendor_id;
	uint8_t vendor_code;
	uint8_t vendor_length;
} attribute_t;

typedef struct {
	packet_type_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t authenticator[16];
    uint8_t attr_count;
    attribute_t* attr;

} radius_packet_t;

radius_packet_t* init_radius_packet();
attribute_t* attribute_init();
void log_packet_data(radius_packet_t* packet);
bool parse_radius_packet(const char* data, ssize_t data_len, radius_packet_t* packet);
char* get_request_type_str(uint8_t code);
char* get_attr_name(uint8_t code);
attribute_t* get_attr_from_pkt(radius_packet_t* packet, uint8_t code);
void dinit_radius_packet(radius_packet_t* packet);
