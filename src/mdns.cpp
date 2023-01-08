#include "mdns_cpp/mdns.hpp"

#include "mdns.h"

#include "internal_utils.hpp"

#include <iostream>


namespace mdns_cpp
{

std::vector<Record> RunServiceDiscovery()
{
    std::vector<int> sockets = OpenClientSockets(0);
    const int num_sockets = static_cast<int>(sockets.size());
	if (sockets.empty()) {
		printf("Failed to open any client sockets\n");
		return {};
	}
	printf("Opened %d socket%s for DNS-SD\n", num_sockets, num_sockets > 1 ? "s" : "");

	printf("Sending DNS-SD discovery\n");
	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_discovery_send(sockets[isock])) {
			printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
        }
	}

    std::array<uint8_t, 2048> buffer;
	std::vector<Record> recordsOut;
	size_t records;

	// This is a simple implementation that loops for <timeout> seconds or as long as we get replies
	int res;
	printf("Reading DNS-SD replies\n");
	do {
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 10000; // Seems to need at least 1ms to discover stuff

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					recordsOut.push_back(Record());
					Record& record = recordsOut.back();
					records += mdns_discovery_recv(sockets[isock], buffer.data(), buffer.size(), QueryCallback,
					                               &record);

					std::cout << "Got record: " << record << "\n";
				}
			}
		}
	} while (res > 0);

	for (int isock = 0; isock < num_sockets; ++isock) {
		mdns_socket_close(sockets[isock]);
    }
	printf("Closed socket%s\n", num_sockets ? "s" : "");

    return recordsOut;
}   



// class Discovery::DiscoveryImpl
// {
// // public:
// //     DiscoveryImpl(DiscoverySettings settings)
// //     : m_settings(std::move(settings))
// //     {
// //         struct sockaddr_in sockaddr;
// //         sockaddr.sin_port = MDNS_PORT;
// //         m_socket = mdns_socket_open_ipv4(&sockaddr);
// //         if (m_socket < -1) {
// //             Log(LogLevel::Error, "Failed to open socket.");
// //         } else {
// //             Log(LogLevel::Debug, "Socket opened as " + std::to_string(m_socket));
// //         }
// //     }

// //     ~DiscoveryImpl()
// //     {   
// //         if (m_socket >= 0) {
// //             mdns_socket_close(m_socket);
// //         }
// //     }

// // private:
// //     void Log(LogLevel level, std::string&& log) {
// //         if (m_settings.logger_callback) {
// //             m_settings.logger_callback(level, std::move(log));
// //         }
// //     }

// // private:
// //     DiscoverySettings m_settings;
// //     int m_socket{-1};

// }; // class Discovery::DiscoveryImpl

// Discovery::Discovery(DiscoverySettings settings)
// // : m_impl(std::make_unique<DiscoveryImpl>(std::move(settings)))
// {}

// Discovery::~Discovery() {}


}