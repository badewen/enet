#ifndef __ENET_SOCKS5_H__
#define __ENET_SOCKS5_H__

#include "enet/types.h"

#define ENET_SOCKS5_VERSION 0x05
#define ENET_SOCKS5_USER_PW_NEGOTIATION_VERSION 0x01

typedef enum _ENetSocks5AuthMethod
{
	ENET_SOCKS5_AUTH_METHOD_NO_AUTH = 0,
	ENET_SOCKS5_AUTH_METHOD_GSSAPI = 1,
	ENET_SOCKS5_AUTH_METHOD_USER_PW = 2, // username and password
	ENET_SOCKS5_AUTH_METHOD_NOT_AVAIL = 0xff
} ENetSocks5AuthMethod;

typedef enum _ENetSocks5ControlCommand
{
	ENET_SOCKS5_CONTROL_COMMAND_CONNECT = 1,
	ENET_SOCKS5_CONTROL_COMMAND_BIND = 2,
	ENET_SOCKS5_CONTROL_COMMAND_UDP_ASSOCIATE = 3
} ENetSocks5ControlCommand;

typedef enum _ENetSocks5AddressType
{
	ENET_SOCKS5_ADDRESS_TYPE_IPV4 = 1,
	ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME = 3,
	ENET_SOCKS5_ADDRESS_TYPE_IPV6 = 4,
} ENetSocks5AddressType;

typedef enum _ENetSocks5ResponseCode
{
	ENET_SOCKS5_RESPONSE_CODE_SUCCEEDED = 0,
	ENET_SOCKS5_RESPONSE_CODE_SERVER_FAILURE = 1,
	ENET_SOCKS5_RESPONSE_CODE_NOT_ALLOWED = 2,
	ENET_SOCKS5_RESPONSE_CODE_NET_UNREACHABLE = 3,
	ENET_SOCKS5_RESPONSE_CODE_HOST_UNREACHABLE = 4,
	ENET_SOCKS5_RESPONSE_CODE_CONN_REFUSED = 5,
	ENET_SOCKS5_RESPONSE_CODE_TTL_EXPIRED = 6,
	ENET_SOCKS5_RESPONSE_CODE_CMD_NOT_SUPPORTED = 7,
	ENET_SOCKS5_RESPONSE_CODE_ADDR_TYPE_NOT_SUPPORTED = 8
} ENetSocks5ResponseCode;

// here a quite vague status codes.
typedef enum _ENetSocks5Status
{
	ENET_SOCKS5_STATUS_SUCCESS = 0,
	ENET_SOCKS5_STATUS_SOCKET_ERR = -1, // Error with socket operation. 
	ENET_SOCKS5_STATUS_INVALID_PARAM = -2, // Parameter is invalid. ex: mandatory parameter is null. 
	ENET_SOCKS5_STATUS_UNSUPPORTED_METHOD = -3,
	ENET_SOCKS5_STATUS_WRONG_CREDENTIAL = -4,
	ENET_SOCKS5_STATUS_MEMORY_ERROR = -5, // memory related errors. such as : malloc failed, etc.
	ENET_SOCKS5_STATUS_SOCKOPT_ERROR = -6,
	ENET_SOCKS5_STATUS_MALFORMED_RESPONSE = -7,
	ENET_SOCKS5_STATUS_MISMATCHED_VERSION = -8,
	ENET_SOCKS5_STATUS_UNSUPPORTED_ADDRESS_TYPE = -9,
	ENET_SOCKS5_STATUS_GENERAL_SERVER_FAILURE = -10, // indicates that the resp code returned by server in controlMsgResp is not successful
	ENET_SOCKS5_STATUS_HOSTNAME_ERROR = -11, // this is returned IF the address type is domain name and fails to resolve into an ip address OR if the ipaddress is invalid.
	ENET_SOCKS5_STATUS_CONTROL_SOCKET_CLOSED = -12,
} ENetSocks5Status;

static const enet_uint8 enetSocks5SupportedAuthMethod[2] = {
	ENET_SOCKS5_AUTH_METHOD_NO_AUTH,
	ENET_SOCKS5_AUTH_METHOD_USER_PW
};

static const enet_uint8 enetSocks5SupportedAddrType[2] = {
	ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME,
	ENET_SOCKS5_ADDRESS_TYPE_IPV4
};

#endif