#include <enet/enet.h>

#include <stdio.h>	

int main() {
	enet_initialize();

	ENetAddress bindAddress;
	bindAddress.host = ENET_HOST_ANY;
	bindAddress.port = 9324;

	ENetHost* host = enet_host_create(&bindAddress, 10, 0, 0, 0);

	//host->usingNewPacketForServer = true // if you want to use growtopia's new "protocol"

	host->checksum = enet_crc32;

	if (host == NULL) {
		printf("Failed to create host.\n");
		exit(1);
	}

	printf("Server is ready\n");

	while (1) {
		ENetEvent event;
		if (enet_host_service(host, &event, 10) > 0) {
			switch (event.type)
			{
			case ENET_EVENT_TYPE_CONNECT: {
				printf("Peer connected!\n");
				break;
			}
			case ENET_EVENT_TYPE_RECEIVE: {
				printf("Echoing Received data back from client %s\n", event.packet->data);
				enet_peer_send(event.peer, 0, event.packet);
				break;	
			}
			case ENET_EVENT_TYPE_DISCONNECT: {
				printf("Peer disconnected.\n");
				break;
			}
			default:
				break;
			}
		}
	}

	enet_host_destroy(host);

	return 0;
}