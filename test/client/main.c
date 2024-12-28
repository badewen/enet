#include <enet/enet.h>

#include <stdio.h>

int main() {
	enet_initialize();

	ENetAddress socks5ServerAddress; 
	enet_address_set_host(&socks5ServerAddress, "127.0.0.1");
	socks5ServerAddress.port = 56479;

	ENetSocks5Tunnel* tunnel = enet_socks5_create(&socks5ServerAddress, "username", "password");

	if (tunnel == NULL) {
		printf("Cant create tunnel\n");
		exit(1);
	}

	printf("connecting\n");
	ENetSocks5Status status = enet_socks5_connect(tunnel);

	if (status != ENET_SOCKS5_STATUS_SUCCESS) {
		printf("failed to connect to socks5 server %d\n", status);
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	printf("authenticating\n");
	status = enet_socks5_authenticate(tunnel);

	if (status != ENET_SOCKS5_STATUS_SUCCESS) {
		printf("failed to authenticate to socks5 server %d\n", status);
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	printf("requesting udp relay\n");

	status = enet_socks5_open_udp(tunnel, NULL);

	if (status != ENET_SOCKS5_STATUS_SUCCESS) {
		printf("failed to open udp %d\n", status);
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	printf("connecting to udp relay\n");

	char udpRelayHost[255];
	enet_address_get_host(&tunnel->udpAddress, udpRelayHost, sizeof(udpRelayHost));
	printf("Udp relay address and port %s:%d\n", udpRelayHost, tunnel->udpAddress.port);

	status = enet_socsk5_connect_udp_socket(tunnel);

	if (status != ENET_SOCKS5_STATUS_SUCCESS) {
		printf("failed to connect to udp relay. %d\n", status);
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	printf("connected to udp relay\n");

	ENetAddress targetAddress;
	enet_address_set_host(&targetAddress, "127.0.0.1");
	targetAddress.port = 9324;

	ENetHost* host = enet_host_create(NULL, 1, 0, 0, 0);

	if (host == NULL) {
		printf("Failed to create host.\n");
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	enet_host_use_socks5(host, tunnel);
	//host->usingNewPacket = true // if you want to use the growtopia new "protocol"

	printf("Connecting to target address\n");

	ENetPeer* peer = enet_host_connect(host, &targetAddress, 2, 0);

	if (peer == NULL) {
		printf("No available peers for initiating an ENet connection.\n");
		enet_socsk5_destroy(tunnel);
		exit(1);
	}

	host->checksum = enet_crc32;

	while (1) {
		ENetEvent event;
		if (enet_host_service(host, &event, 10) > 0) {
			switch (event.type)
			{
			case ENET_EVENT_TYPE_CONNECT: {
				printf("Connected to target server\n");
				
				const char* data = "Hallo dunia dari client";
				enet_peer_send(event.peer, 0, enet_packet_create(data, strlen(data), ENET_PACKET_FLAG_RELIABLE));

				break;
			}
			case ENET_EVENT_TYPE_RECEIVE: {
				printf("Received data %s\n", event.packet->data);
				break;	
			}
			case ENET_EVENT_TYPE_DISCONNECT: {
				printf("Disconnected from server. Either disconnected from tunnel or the target server.\n");
				break;
			}
			default:
				break;
			}
		}
	}

	enet_socsk5_destroy(tunnel);
	enet_host_destroy(host);

	return 0;
}