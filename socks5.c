#include "enet/enet.h"
#include <stdio.h>
#include <string.h>

// this contains like the most boring-boilerplate-repeating code that i have to write zzzzz...
// if anyone is looking at this code, im sorry. I gotta follow the original code style lol
// peak enet_malloc and enet_free gameplay

static int
enet_socks5_is_auth_method_supported(ENetSocks5AuthMethod method)
{
	int found = 0;
	for (size_t i = 0; i < sizeof(enetSocks5SupportedAuthMethod); i++) {
		if (method == enetSocks5SupportedAuthMethod[i]) {
			found = 1;
			break;
		}
	}

	return found;
}

static int
enet_socks5_is_addr_type_supported(ENetSocks5AddressType addrType)
{
	int found = 0;
	for (size_t i = 0; i < sizeof(enetSocks5SupportedAddrType); i++) {
		if (addrType == enetSocks5SupportedAddrType[i]) {
			found = 1;
			break;
		}
	}

	return found;
}

static void
enet_socks5_destroy_buffer(ENetBuffer* buff)
{
	if (buff != NULL)
		enet_free(buff->data);

	enet_free((void*)buff);
}

static ENetBuffer*
enet_socks5_create_buffer(size_t size)
{
	ENetBuffer* buffer = (ENetBuffer*)enet_malloc(sizeof(ENetBuffer));

	if (buffer == NULL) {
		enet_free(buffer);

		return NULL;
	}

	memset(buffer, 0, sizeof(ENetBuffer));

	buffer->data = enet_malloc(size);
	buffer->dataLength = size;

	if (buffer->data == NULL) {
		enet_free(buffer->data);
		enet_free(buffer);

		return NULL;
	}

	memset(buffer->data, 0, size);

	return buffer;
}

static ENetBuffer*
enet_socks5_create_buff_from_method_selection_req(const ENetSocks5MethodSelectionReq* req)
{
	if (req == NULL)
		return NULL;


	ENetBuffer* buffer = enet_socks5_create_buffer(sizeof(enet_uint16) + sizeof(enet_uint8) * req->numMethods);

	if (buffer == NULL) {
		enet_socks5_destroy_buffer(buffer);

		return NULL;
	}

	memset((enet_uint8*)(buffer->data), 5, 1);
	memset((enet_uint8*)(buffer->data) + 1, req->numMethods, 1);
	memcpy((enet_uint8*)(buffer->data) + 2, req->methods, req->numMethods);

	return buffer;
}

static void
enet_socks5_destroy_method_selection_req(ENetSocks5MethodSelectionReq* req)
{
	if (req == NULL)
		return;

	enet_free(req->methods);
	enet_free(req);
}

static ENetSocks5MethodSelectionReq*
enet_socks5_create_method_selection_req(enet_uint8 methodNum, const enet_uint8 methods[]) {
	if (methods == NULL)
		return NULL;

	ENetSocks5MethodSelectionReq* req = (ENetSocks5MethodSelectionReq*)enet_malloc(sizeof(ENetSocks5MethodSelectionReq));

	if (req == NULL) {
		enet_free(req);

		return NULL;
	}

	memset(req, 0, sizeof(ENetSocks5MethodSelectionReq));
	req->version = 0x5;
	req->numMethods = methodNum;
	req->methods = (ENetSocks5AuthMethod*)enet_malloc(sizeof(enet_uint8) * req->numMethods);

	if (req->methods == NULL) {
		enet_free(req->methods);
		enet_free(req);

		return NULL;
	}

	memcpy(req->methods, methods, sizeof(enet_uint8) * req->numMethods);

	return req;
}

static ENetSocks5MethodSelectionResp*
enet_socks5_create_from_buff_method_selection_resp(const ENetBuffer* buff)
{
	if (buff->dataLength != 2 || buff->data == NULL) {
		return NULL;
	}

	ENetSocks5MethodSelectionResp* resp = (ENetSocks5MethodSelectionResp*)enet_malloc(sizeof(ENetSocks5MethodSelectionResp));

	if (resp == NULL) {
		enet_free(resp);

		return NULL;
	}

	memset(resp, 0, sizeof(ENetSocks5MethodSelectionResp));

	memcpy(&(resp->version), buff->data, sizeof(enet_uint8));
	memcpy(&(resp->method), ((enet_uint8*)(buff->data)) + 1, sizeof(enet_uint8));

	return resp;
}

static void
enet_socks5_destroy_method_selection_resp(ENetSocks5MethodSelectionResp* resp)
{
	if (resp == NULL)
		return;

	enet_free(resp);
}

static ENetSocks5UserPwAuthReq*
enet_socks5_create_user_pw_auth_req(const char* username, const char* password)
{
	if (strlen(username) > 255 || strlen(password) > 255) {
		return NULL;
	}

	ENetSocks5UserPwAuthReq* req = (ENetSocks5UserPwAuthReq*)enet_malloc(sizeof(ENetSocks5UserPwAuthReq));

	if (req == NULL) {
		enet_free(req);

		return NULL;
	}

	memset(req, 0, sizeof(ENetSocks5UserPwAuthReq));

	req->version = ENET_SOCKS5_USER_PW_NEGOTIATION_VERSION; // rfc1929 subnegotiation version
	req->usernameLen = (enet_uint8)strlen(username);
	req->passwordLen = (enet_uint8)strlen(password);

	req->username = (char*)enet_malloc(req->usernameLen + 1);
	if (req->username == NULL) {
		enet_free(req->username);
		enet_free(req);

		return NULL;
	}
	memset(req->username, 0, req->usernameLen + 1);
	memcpy(req->username, username, req->usernameLen);

	req->password = (char*)enet_malloc(req->passwordLen + 1);
	if (req->password == NULL) {
		enet_free(req->password);
		enet_free(req->username);
		enet_free(req);

		return NULL;
	}
	memset(req->password, 0, req->passwordLen + 1);
	memcpy(req->password, password, req->passwordLen);

	return req;
}

static void
enet_socks5_destroy_user_pw_auth_req(ENetSocks5UserPwAuthReq* req)
{
	if (req == NULL) {
		return;
	}

	enet_free(req->username);
	enet_free(req->password);
	enet_free(req);
}

static ENetBuffer*
enet_socks5_create_buff_from_user_pw_auth_req(const ENetSocks5UserPwAuthReq* req)
{
	if (req == NULL) {
		return NULL;
	}

	if (req->password == NULL || req->username == NULL) {
		return NULL;
	}

	ENetBuffer* buff = enet_socks5_create_buffer((sizeof(enet_uint8) * 3) + req->usernameLen + req->passwordLen);

	if (buff == NULL) {
		return NULL;
	}

	memset(buff->data, req->version, 1);
	memset((enet_uint8*)(buff->data) + 1, req->usernameLen, 1);
	memcpy((enet_uint8*)(buff->data) + 2, req->username, req->usernameLen);
	memset((enet_uint8*)(buff->data) + 2 + req->usernameLen, req->passwordLen, 1);
	memcpy((enet_uint8*)(buff->data) + 2 + req->usernameLen + 1, req->password, req->passwordLen);

	return buff;
}

static ENetSocks5UserPwAuthResp*
enet_socks5_create_from_buff_auth_status_resp(const ENetBuffer* buffer)
{
	if (buffer == NULL || buffer->data == NULL || buffer->dataLength != 2) {
		return NULL;
	}

	ENetSocks5UserPwAuthResp* resp = (ENetSocks5UserPwAuthResp*)enet_malloc(sizeof(ENetSocks5UserPwAuthResp));

	if (resp == NULL) {
		enet_free(resp);

		return NULL;
	}

	memset(resp, 0, sizeof(ENetSocks5UserPwAuthResp));

	memcpy(&(resp->version), buffer->data, sizeof(enet_uint8));
	memcpy(&(resp->not_success), (enet_uint8*)(buffer->data) + 1, 1);

	return resp;
}

static void
enet_socks5_destroy_auth_status_resp(ENetSocks5UserPwAuthResp* resp)
{
	if (resp == NULL) {
		return;
	}

	enet_free(resp);
}

// address depends on the addrType.
static ENetSocks5ControlMsgReq*
enet_socks5_create_control_msg_req(ENetSocks5ControlCommand cmd, ENetSocks5AddressType addrType, void* address, enet_uint16 port)
{
	if (address == NULL) {
		return NULL;
	}

	ENetSocks5ControlMsgReq* req = (ENetSocks5ControlMsgReq*)enet_malloc(sizeof(ENetSocks5ControlMsgReq));

	if (req == NULL) {
		enet_free(req);

		return NULL;
	}

	req->version = ENET_SOCKS5_VERSION;
	req->command = cmd;
	req->reserved = 0;
	req->addressType = addrType;

	if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		req->dstAddr.domainName = (char*)enet_malloc(strlen((const char*)address) + 1);
		memset((void*)req->dstAddr.domainName, 0, strlen((const char*)address) + 1);

		if (req->dstAddr.domainName == NULL) {
			enet_free((void*)req->dstAddr.domainName);
			enet_free(req);

			return NULL;
		}

		strcpy((char*)req->dstAddr.domainName, (char*)address);
	}
	else if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy(&req->dstAddr.ipv4, address, sizeof(enet_uint32));
	}
	else {
		enet_free(req);

		return NULL;
	}

	req->dstPort = port;

	return req;
}

static void
enet_socks5_destroy_control_msg_req(ENetSocks5ControlMsgReq* req)
{
	if (req == NULL) {
		return;
	}

	if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		enet_free(req->dstAddr.domainName);
	}

	enet_free(req);
}

static ENetBuffer*
enet_socks5_create_buff_from_control_msg_req(ENetSocks5ControlMsgReq* req)
{
	if (req == NULL) {
		return NULL;
	}

	size_t addressSize = 0;

	if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		addressSize = strlen(req->dstAddr.domainName) + 1; 		// len + char array
	}
	else if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		addressSize = sizeof(enet_uint8) * 4;
	}
	else {
		return NULL;
	}

	ENetBuffer* buffer = enet_socks5_create_buffer((sizeof(enet_uint8) * 6) + addressSize);

	if (buffer == NULL) {
		enet_socks5_destroy_buffer(buffer);

		return NULL;
	}

	memset(buffer->data, ENET_SOCKS5_VERSION, 1);
	memset((enet_uint8*)buffer->data + 1, req->command, 1);
	memset((enet_uint8*)buffer->data + 2, 0, 1);
	memset((enet_uint8*)buffer->data + 3, req->addressType, 1);

	if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		// -1 to exclude the length byte.
		memset((enet_uint8*)buffer->data + 4, addressSize - 1, 1);
		memcpy((enet_uint8*)buffer->data + 5, req->dstAddr.domainName, addressSize - 1);
	}
	else if (req->addressType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy((enet_uint8*)buffer->data + 4, &req->dstAddr.ipv4, sizeof(enet_uint32));
	}

	*(enet_uint16*)((enet_uint8*)buffer->data + 4 + addressSize) = ENET_HOST_TO_NET_16(req->dstPort);

	return buffer;
}

// status is out variable.
static ENetSocks5ControlMsgResp*
enet_socks5_create_from_buff_control_msg_resp(ENetBuffer* buffer, ENetSocks5Status* status)
{
	if (buffer == NULL || buffer->data == NULL) {
		if (status != NULL)
			*status = ENET_SOCKS5_STATUS_INVALID_PARAM;

		return NULL;
	}

	if (buffer->dataLength > 262 || buffer->dataLength < 7) {
		if (status != NULL)
			*status = ENET_SOCKS5_STATUS_MALFORMED_RESPONSE;

		return NULL;
	}

	ENetSocks5ControlMsgResp* resp = (ENetSocks5ControlMsgResp*)enet_malloc(sizeof(ENetSocks5ControlMsgResp));

	if (resp == NULL) {
		enet_free(resp);

		if (status != NULL)
			*status = ENET_SOCKS5_STATUS_MEMORY_ERROR;

		return NULL;
	}

	resp->version = *((enet_uint8*)buffer->data);
	resp->respCode = (ENetSocks5ResponseCode) * (((enet_uint8*)buffer->data) + 1);
	resp->reserved = *(((enet_uint8*)buffer->data) + 2);
	resp->addrType = (ENetSocks5AddressType) * (((enet_uint8*)buffer->data) + 3);

	if (resp->version != ENET_SOCKS5_VERSION) {
		enet_free(resp);

		if (status != NULL)
			*status = ENET_SOCKS5_STATUS_MISMATCHED_VERSION;
		return NULL;
	}

	if (!enet_socks5_is_addr_type_supported(resp->addrType)) {
		enet_free(resp);

		if (status != NULL)
			*status = ENET_SOCKS5_STATUS_UNSUPPORTED_ADDRESS_TYPE;
		return NULL;
	}


	enet_uint8 addressSize = 0;

	if (resp->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		enet_uint8 stringLength = 0;
		memcpy(&stringLength, ((enet_uint8*)buffer->data) + 4, sizeof(enet_uint8)); // the length octet

		resp->bindAddr.domainName = (char*)enet_malloc(stringLength + 1); //include null terminator	

		if (resp->bindAddr.domainName == NULL) {
			enet_free(resp->bindAddr.domainName);
			enet_free(resp);

			if (status != NULL)
				*status = ENET_SOCKS5_STATUS_MEMORY_ERROR;

			return NULL;
		}

		memset(resp->bindAddr.domainName, 0, stringLength + 1);
		memcpy(resp->bindAddr.domainName, ((enet_uint8*)buffer->data) + 5, stringLength);

		addressSize = stringLength + 1;
	}
	else if (resp->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy(&resp->bindAddr.ipv4, (enet_uint8*)buffer->data + 4, sizeof(enet_uint32));

		addressSize = sizeof(enet_uint32);
	}

	resp->bindPort = ENET_NET_TO_HOST_16(*(enet_uint16*)((enet_uint8*)buffer->data + 4 + addressSize));

	if (status != NULL)
		*status = ENET_SOCKS5_STATUS_SUCCESS;

	return resp;
}

static ENetSocks5UdpHeader*
enet_socks5_create_udp_header(ENetSocks5AddressType addrType, void* address, enet_uint16 port)
{
	if (address == NULL) {
		return NULL;
	}

	ENetSocks5UdpHeader* header = (ENetSocks5UdpHeader*)enet_malloc(sizeof(ENetSocks5UdpHeader));

	if (header == NULL) {
		enet_free(header);

		return NULL;
	}

	header->reserved = 0x0000;
	header->fragNum = 0;
	header->addrType = addrType;

	if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		size_t totalDomainNameSize = strlen((const char*)address) + 1;
		header->dstAddr.domainName = (char*)enet_malloc(totalDomainNameSize);

		if (header->dstAddr.domainName == NULL) {
			enet_free(header->dstAddr.domainName);
			enet_free(header);

			return NULL;
		}

		memcpy(header->dstAddr.domainName, address, totalDomainNameSize);
	}
	else if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy(&header->dstAddr.ipv4, address, sizeof(enet_uint32));
	}
	else {
		enet_free(header);

		return NULL;
	}

	header->dstPort = port;

	return header;
}

static void
enet_socks5_destroy_control_msg_resp(ENetSocks5ControlMsgResp* resp)
{
	if (resp == NULL)
		return;

	if (resp->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		enet_free(resp->bindAddr.domainName);
	}

	enet_free(resp);
}

static ENetBuffer*
enet_socks5_create_buff_from_udp_header(ENetSocks5UdpHeader* header)
{
	if (header == NULL) {
		return NULL;
	}

	size_t addressSize = 0;

	if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		addressSize = strlen(header->dstAddr.domainName) + 1; 		// len + char array
	}
	else if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		addressSize = sizeof(enet_uint8) * 4;
	}
	else {
		return NULL;
	}

	ENetBuffer* buffer = enet_socks5_create_buffer((sizeof(enet_uint8) * 6) + addressSize);

	if (buffer == NULL) {
		enet_socks5_destroy_buffer(buffer);

		return NULL;
	}

	memset(buffer->data, 0, 2);
	memset((enet_uint8*)buffer->data + 2, 0, 1);
	memcpy((enet_uint8*)buffer->data + 3, &header->addrType, 1);

	if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		// -1 to exclude the length byte.
		memset((enet_uint8*)buffer->data + 4, addressSize - 1, 1);
		memcpy((enet_uint8*)buffer->data + 5, header->dstAddr.domainName, addressSize - 1);
	}
	else if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy((enet_uint8*)buffer->data + 4, &header->dstAddr.ipv4, sizeof(enet_uint32));
	}

	*((enet_uint16*)((enet_uint8*)buffer->data + 4 + addressSize)) = ENET_HOST_TO_NET_16(header->dstPort);

	return buffer;
}

static void
enet_socks5_destroy_udp_header(ENetSocks5UdpHeader* header)
{
	if (header == NULL) {
		return;
	}

	if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		enet_free(header->dstAddr.domainName);
	}

	enet_free(header);
}

static ENetSocks5UdpHeader*
enet_socks5_extract_form_buff_udp_header(ENetBuffer* buffer, size_t* headerSize)
{
	if (headerSize != NULL) {
		*headerSize = 0;
	}

	if (buffer == NULL || buffer->data == NULL || buffer->dataLength < 10) {
		return NULL;
	}

	ENetSocks5UdpHeader* header = (ENetSocks5UdpHeader*)enet_malloc(sizeof(ENetSocks5UdpHeader));
	memset(header, 0, sizeof(ENetSocks5UdpHeader));

	if (header == NULL) {
		enet_free(header);

		return NULL;
	}

	memcpy(&header->reserved, buffer->data, 2);
	memcpy(&header->fragNum, ((enet_uint8*)buffer->data) + 2, 1);
	memcpy(&header->addrType, ((enet_uint8*)buffer->data) + 3, 1);

	size_t totalAddressSize = 0;

	if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		enet_uint8 stringSize = *((enet_uint8*)buffer->data) + 4;

		char* domainName = (char*)enet_malloc(stringSize + 1);
		memset(domainName, 0, stringSize + 1);

		if (domainName == NULL) {
			enet_free(header);
			enet_free(domainName);

			return NULL;
		}

		memcpy(domainName, ((enet_uint8*)buffer->data) + 5, stringSize);

		totalAddressSize = stringSize + 1;
		header->dstAddr.domainName = domainName;
	}
	else if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		memcpy(&header->dstAddr.ipv4, (enet_uint8*)buffer->data + 4, 4);
		totalAddressSize = 4;
	}

	header->dstPort = ENET_NET_TO_HOST_16(*(enet_uint16*)((enet_uint8*)buffer->data + 4 + totalAddressSize));

	if (headerSize != NULL) {
		*headerSize = 4 + totalAddressSize + 2;
	}

	return header;
}

ENetSocks5Tunnel*
enet_socks5_create(const ENetAddress* socks5Address, const char* username, const char* password)
{
	ENetSocks5Tunnel* tunnel = (ENetSocks5Tunnel*)enet_malloc(sizeof(ENetSocks5Tunnel));
	memset(tunnel, 0, sizeof(ENetSocks5Tunnel));

	if (tunnel == NULL) {
		enet_free(tunnel);

		return NULL;
	}

	if (socks5Address != NULL) {
		tunnel->controlTcpAddress.host = socks5Address->host;
		tunnel->controlTcpAddress.port = socks5Address->port;
	}

	tunnel->controlTcpSocket = enet_socket_create(ENET_SOCKET_TYPE_STREAM);

	if (tunnel->controlTcpSocket == ENET_SOCKET_NULL) {
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (enet_socket_set_option(tunnel->controlTcpSocket, ENET_SOCKOPT_NODELAY, 1) < 0) {
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (enet_socket_set_option(tunnel->controlTcpSocket, ENET_SOCKOPT_NONBLOCK, 0) < 0) {
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (enet_socket_set_option(tunnel->controlTcpSocket, ENET_SOCKOPT_RCVTIMEO, 60000) < 0) { // wait 1 minute
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (enet_socket_set_option(tunnel->controlTcpSocket, ENET_SOCKOPT_SNDTIMEO, 60000) < 0) { // wait 1 minute
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (enet_socket_set_option(tunnel->controlTcpSocket, ENET_SOCKOPT_KEEPALIVE, 1) < 0) { // keepalive
		enet_socket_destroy(tunnel->controlTcpSocket);

		enet_free(tunnel);

		return NULL;
	}

	if (username != NULL) {
		size_t usernameLen = strlen(username);

		tunnel->username = (char*)enet_malloc(usernameLen + 1);
		memset(tunnel->username, 0, usernameLen + 1);

		if (tunnel->username == NULL) {
			enet_socket_destroy(tunnel->controlTcpSocket);

			enet_free(tunnel->username);
			enet_free(tunnel);

			return NULL;
		}

		memcpy(tunnel->username, username, usernameLen);
	}

	if (password != NULL) {
		size_t passwordLen = strlen(password);

		tunnel->password = (char*)enet_malloc(passwordLen + 1);
		memset(tunnel->password, 0, passwordLen + 1);

		if (tunnel->password == NULL) {
			enet_socket_destroy(tunnel->controlTcpSocket);

			enet_free(tunnel->username);
			enet_free(tunnel->password);
			enet_free(tunnel);

			return NULL;
		}

		memcpy(tunnel->password, password, passwordLen);
	}

	return tunnel;
}

ENetSocks5Status
enet_socks5_connect(ENetSocks5Tunnel* tunnel)
{
	if (tunnel == NULL) {
		return ENET_SOCKS5_STATUS_INVALID_PARAM;
	}

	if (enet_socket_connect(tunnel->controlTcpSocket, &tunnel->controlTcpAddress) < 0) {
		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	return ENET_SOCKS5_STATUS_SUCCESS;
}

ENetSocks5Status
enet_socks5_authenticate(ENetSocks5Tunnel* tunnel)
{
	if (tunnel == NULL) {
		return ENET_SOCKS5_STATUS_INVALID_PARAM;
	}

	ENetSocks5MethodSelectionReq* methodSelReq =
		enet_socks5_create_method_selection_req(sizeof(enetSocks5SupportedAuthMethod), enetSocks5SupportedAuthMethod);

	if (methodSelReq == NULL) {
		enet_socks5_destroy_method_selection_req(methodSelReq);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	ENetBuffer* buffer =
		enet_socks5_create_buff_from_method_selection_req(methodSelReq);

	if (buffer == NULL) {
		enet_socks5_destroy_buffer(buffer);
		enet_socks5_destroy_method_selection_req(methodSelReq);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	if (enet_socket_send(tunnel->controlTcpSocket, NULL, buffer, 1) < 0) {
		enet_socks5_destroy_buffer(buffer);
		enet_socks5_destroy_method_selection_req(methodSelReq);

		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	enet_socks5_destroy_buffer(buffer);
	enet_socks5_destroy_method_selection_req(methodSelReq);

	enet_uint8 methodSelRespRawBuffer[2] = { 0 };

	ENetBuffer methodSelRespBuffer = {
		.dataLength = sizeof(methodSelRespRawBuffer),
		.data = methodSelRespRawBuffer
	};

	size_t recvLength = 0;
	if ((recvLength = enet_socket_receive(tunnel->controlTcpSocket, NULL, &methodSelRespBuffer, 1)) < 0) {
		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	if (recvLength == 0) {
		return ENET_SOCKS5_STATUS_MALFORMED_RESPONSE;
	}

	ENetSocks5MethodSelectionResp* methodSelResp = enet_socks5_create_from_buff_method_selection_resp(&methodSelRespBuffer);

	if (methodSelResp == NULL) {
		enet_socks5_destroy_method_selection_resp(methodSelResp);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}
	else if (methodSelResp->version != ENET_SOCKS5_VERSION) {
		enet_socks5_destroy_method_selection_resp(methodSelResp);

		return ENET_SOCKS5_STATUS_MISMATCHED_VERSION;
	}
	else if (!enet_socks5_is_auth_method_supported(methodSelResp->method)) {
		enet_socks5_destroy_method_selection_resp(methodSelResp);

		return ENET_SOCKS5_STATUS_UNSUPPORTED_METHOD;
	}

	if (methodSelResp->method == ENET_SOCKS5_AUTH_METHOD_USER_PW) {
		ENetSocks5UserPwAuthReq* userPwAuthReq = enet_socks5_create_user_pw_auth_req(tunnel->username, tunnel->password);

		if (userPwAuthReq == NULL) {
			enet_socks5_destroy_user_pw_auth_req(userPwAuthReq);

			return ENET_SOCKS5_STATUS_MEMORY_ERROR;
		}

		ENetBuffer* userPwAuthReqBuff = enet_socks5_create_buff_from_user_pw_auth_req(userPwAuthReq);
		enet_socks5_destroy_user_pw_auth_req(userPwAuthReq);

		if (userPwAuthReqBuff == NULL) {
			enet_socks5_destroy_buffer(userPwAuthReqBuff);

			return ENET_SOCKS5_STATUS_MEMORY_ERROR;
		}

		if (enet_socket_send(tunnel->controlTcpSocket, NULL, userPwAuthReqBuff, 1) < 0) {
			enet_socks5_destroy_buffer(userPwAuthReqBuff);

			return ENET_SOCKS5_STATUS_SOCKET_ERR;
		}

		enet_socks5_destroy_buffer(userPwAuthReqBuff);

		enet_uint8 authStatusRespRawBuff[2] = { 0 };
		//memset(authStatusRespRawBuff, 0, sizeof(authStatusRespRawBuff));

		ENetBuffer authStatusRespBuff = {
			.dataLength = sizeof(authStatusRespRawBuff),
			.data = authStatusRespRawBuff
		};

		if ((recvLength = enet_socket_receive(tunnel->controlTcpSocket, NULL, &authStatusRespBuff, 1)) < 0) {
			return ENET_SOCKS5_STATUS_SOCKET_ERR;
		}

		if (recvLength == 0) {
			return ENET_SOCKS5_STATUS_MALFORMED_RESPONSE;
		}

		ENetSocks5UserPwAuthResp* authStatusResp = enet_socks5_create_from_buff_auth_status_resp(&authStatusRespBuff);

		if (authStatusResp == NULL) {
			enet_socks5_destroy_auth_status_resp(authStatusResp);

			return ENET_SOCKS5_STATUS_MEMORY_ERROR;
		}

		if (authStatusResp->version != ENET_SOCKS5_USER_PW_NEGOTIATION_VERSION) {
			enet_socks5_destroy_auth_status_resp(authStatusResp);

			return ENET_SOCKS5_STATUS_MISMATCHED_VERSION;
		}

		if (authStatusResp->not_success) {
			enet_socks5_destroy_auth_status_resp(authStatusResp);

			return ENET_SOCKS5_STATUS_WRONG_CREDENTIAL;
		}

		enet_socks5_destroy_auth_status_resp(authStatusResp);
	}

	return ENET_SOCKS5_STATUS_SUCCESS;
}


// respCode is optional. if specified, will write the ENetSocks5ControlMsgResp into respCode.
ENetSocks5Status
enet_socks5_open_udp(ENetSocks5Tunnel* tunnel, ENetSocks5ResponseCode* respCode)
{
	if (tunnel == NULL || tunnel->controlTcpSocket == ENET_SOCKET_NULL) {
		return ENET_SOCKS5_STATUS_INVALID_PARAM;
	}

	enet_uint32 dstAddr = 0;
	ENetSocks5ControlMsgReq* controlMsgReq = enet_socks5_create_control_msg_req(
		ENET_SOCKS5_CONTROL_COMMAND_UDP_ASSOCIATE,
		ENET_SOCKS5_ADDRESS_TYPE_IPV4,
		&tunnel->udpAddress.host, tunnel->udpAddress.port
	);

	if (controlMsgReq == NULL) {
		enet_socks5_destroy_control_msg_req(controlMsgReq);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	ENetBuffer* controlMsgReqBuff = enet_socks5_create_buff_from_control_msg_req(controlMsgReq);
	enet_socks5_destroy_control_msg_req(controlMsgReq);

	if (controlMsgReqBuff == NULL) {
		enet_socks5_destroy_buffer(controlMsgReqBuff);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	if (enet_socket_send(tunnel->controlTcpSocket, NULL, controlMsgReqBuff, 1) < 0) {
		enet_socks5_destroy_buffer(controlMsgReqBuff);

		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}
	enet_socks5_destroy_buffer(controlMsgReqBuff);

	enet_uint8 controlMsgRespRawBuff[262] = { 0 }; // maximum size
	//memset(controlMsgRespRawBuff, 0, sizeof(controlMsgRespRawBuff));
	ENetBuffer controlMsgRespBuff = {
		.dataLength = sizeof(controlMsgRespRawBuff),
		.data = controlMsgRespRawBuff
	};

	size_t recvLength = 0;
	if ((recvLength = enet_socket_receive(tunnel->controlTcpSocket, NULL, &controlMsgRespBuff, 1)) < 0) {
		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	if (recvLength == 0) {
		return ENET_SOCKS5_STATUS_MALFORMED_RESPONSE;
	}

	ENetSocks5Status createFromBufferStatus;
	ENetSocks5ControlMsgResp* controlMsgResp = enet_socks5_create_from_buff_control_msg_resp(&controlMsgRespBuff, &createFromBufferStatus);

	if (createFromBufferStatus != ENET_SOCKS5_STATUS_SUCCESS) {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return createFromBufferStatus;
	}

	if (controlMsgResp == NULL) {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	if (!enet_socks5_is_addr_type_supported(controlMsgResp->addrType)) {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return ENET_SOCKS5_STATUS_UNSUPPORTED_ADDRESS_TYPE;
	}

	if (respCode != NULL)
		*respCode = controlMsgResp->respCode;

	if (controlMsgResp->respCode != ENET_SOCKS5_RESPONSE_CODE_SUCCEEDED) {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return ENET_SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
	}

	if (controlMsgResp->version != ENET_SOCKS5_VERSION) {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return ENET_SOCKS5_STATUS_MISMATCHED_VERSION;
	}

	ENetAddress udpRelayAddress;
	udpRelayAddress.port = controlMsgResp->bindPort;

	if (controlMsgResp->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
		if (enet_address_set_host(&udpRelayAddress, controlMsgResp->bindAddr.domainName) < 0) {
			enet_socks5_destroy_control_msg_resp(controlMsgResp);

			return ENET_SOCKS5_STATUS_HOSTNAME_ERROR;
		}
	}
	else if (controlMsgResp->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
		udpRelayAddress.host = controlMsgResp->bindAddr.ipv4;
		if (udpRelayAddress.host == 0) {
			udpRelayAddress.host = tunnel->controlTcpAddress.host;
		}
	}
	else {
		enet_socks5_destroy_control_msg_resp(controlMsgResp);

		return ENET_SOCKS5_STATUS_UNSUPPORTED_ADDRESS_TYPE;
	}
	enet_socks5_destroy_control_msg_resp(controlMsgResp);

	tunnel->udpAddress = udpRelayAddress;

	return ENET_SOCKS5_STATUS_SUCCESS;
}

ENetSocks5Status
enet_socsk5_connect_udp_socket(ENetSocks5Tunnel* tunnel)
{
	if (tunnel == NULL)
		return ENET_SOCKS5_STATUS_INVALID_PARAM;

	int socketError = 0; // a simple hack to check if the tcp connection is closed or not.
	if (enet_socket_get_option(tunnel->controlTcpSocket, ENET_SOCKOPT_ERROR, &socketError) < 0) {
		return ENET_SOCKS5_STATUS_CONTROL_SOCKET_CLOSED;
	}

	tunnel->udpSocket = enet_socket_create(ENET_SOCKET_TYPE_DATAGRAM);
	if (tunnel->udpSocket == ENET_SOCKET_NULL) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	if (enet_socket_set_option(tunnel->udpSocket, ENET_SOCKOPT_NONBLOCK, 1) < 0) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKOPT_ERROR;
	}
	if (enet_socket_set_option(tunnel->udpSocket, ENET_SOCKOPT_BROADCAST, 1) < 0) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKOPT_ERROR;
	}
	// 262 is the max socks5 header size
	if (enet_socket_set_option(tunnel->udpSocket, ENET_SOCKOPT_RCVBUF, ENET_HOST_RECEIVE_BUFFER_SIZE + 262) < 0) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKOPT_ERROR;
	}
	// 262 is the max socks5 header size
	if (enet_socket_set_option(tunnel->udpSocket, ENET_SOCKOPT_SNDBUF, ENET_HOST_SEND_BUFFER_SIZE + 262) < 0) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKOPT_ERROR;
	}

	if (enet_socket_connect(tunnel->udpSocket, &tunnel->udpAddress) < 0) {
		enet_socket_destroy(tunnel->udpSocket);

		return ENET_SOCKS5_STATUS_SOCKET_ERR;
	}

	return ENET_SOCKS5_STATUS_SUCCESS;
}

int
enet_socks5_udp_send(ENetSocks5Tunnel* tunnel, ENetAddress* targetAddress, ENetBuffer* buffers, size_t bufferCount)
{
	if (tunnel == NULL || targetAddress == NULL || buffers == NULL || tunnel->udpSocket == ENET_SOCKET_NULL) {
		return ENET_SOCKS5_STATUS_INVALID_PARAM;
	}

	ENetSocks5UdpHeader* udpHeader = enet_socks5_create_udp_header(ENET_SOCKS5_ADDRESS_TYPE_IPV4, &targetAddress->host, targetAddress->port);
	if (udpHeader == NULL) {
		enet_socks5_destroy_udp_header(udpHeader);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	ENetBuffer* udpHeaderBuff = enet_socks5_create_buff_from_udp_header(udpHeader);
	enet_socks5_destroy_udp_header(udpHeader);

	if (udpHeaderBuff == NULL) {
		enet_socks5_destroy_buffer(udpHeaderBuff);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	ENetBuffer* newBuffers = (ENetBuffer*)enet_malloc(sizeof(ENetBuffer) * (bufferCount + 1));

	if (newBuffers == NULL) {
		enet_free(newBuffers);
		enet_socks5_destroy_buffer(udpHeaderBuff);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	newBuffers[0].data = udpHeaderBuff->data;
	newBuffers[0].dataLength = udpHeaderBuff->dataLength;

	memcpy(&newBuffers[1], buffers, sizeof(ENetBuffer) * bufferCount);

	int sentLength = enet_socket_send(tunnel->udpSocket, &tunnel->udpAddress, newBuffers, bufferCount + 1);

	enet_free(newBuffers);
	enet_socks5_destroy_buffer(udpHeaderBuff);

	return sentLength;
}

int
enet_socks5_udp_receive(ENetSocks5Tunnel* tunnel, ENetAddress* address, ENetBuffer* buffers, size_t bufferCount)
{
	enet_uint8 rawRecvBuffer[ENET_PROTOCOL_MAXIMUM_MTU + 262] = { 0 };
	ENetBuffer buffer = {
		.dataLength = sizeof(rawRecvBuffer),
		.data = rawRecvBuffer
	};

	size_t recvLength = enet_socket_receive(tunnel->udpSocket, NULL, &buffer, 1);

	if (recvLength < 1) {
		return recvLength;
	}

	size_t headerSize = 0;
	ENetSocks5UdpHeader* header = enet_socks5_extract_form_buff_udp_header(&buffer, &headerSize);

	if (header == NULL) {
		enet_socks5_destroy_udp_header(header);

		return ENET_SOCKS5_STATUS_MEMORY_ERROR;
	}

	if (address != NULL) {
		if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME) {
			if (enet_address_set_host(address, header->dstAddr.domainName) < 0) {
				enet_socks5_destroy_udp_header(header);

				return ENET_SOCKS5_STATUS_HOSTNAME_ERROR;
			}
		}
		else if (header->addrType == ENET_SOCKS5_ADDRESS_TYPE_IPV4) {
			memcpy(&address->host, &header->dstAddr.ipv4, 4);
			memcpy(&address->port, &header->dstPort, 2);
		}
		else {
			return ENET_SOCKS5_STATUS_UNSUPPORTED_ADDRESS_TYPE;
		}
	}

	memcpy(buffers->data, (enet_uint8*)buffer.data + headerSize, buffer.dataLength - headerSize);

	return recvLength - headerSize;
}

void
enet_socsk5_destroy(ENetSocks5Tunnel* tunnel)
{
	if (tunnel == NULL) {
		return;
	}
	enet_socket_destroy(tunnel->udpSocket);
	enet_socket_destroy(tunnel->controlTcpSocket);
	enet_free(tunnel->username);
	enet_free(tunnel->password);
	enet_free(tunnel);
}

void
enet_host_use_socks5(ENetHost* host, ENetSocks5Tunnel* tunnel)
{
	host->socks5Tunnel = tunnel;
}