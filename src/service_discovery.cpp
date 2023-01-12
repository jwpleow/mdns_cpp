#include "mdns_cpp/service_discovery.hpp"
#include "mdns.h"
#include "mdns_utils.hpp"

#include <fmt/ostream.h>

namespace mdns_cpp
{

// Mostly from send_dns_sd()
std::vector<Record> RunServiceDiscovery()
{
	const auto openedSocketData = OpenClientSockets(0);
    const std::vector<int>& sockets = openedSocketData.sockets;
    const int num_sockets = static_cast<int>(sockets.size());
	if (sockets.empty()) {
		Log(LogLevel::Error, "Failed to open any client sockets");
		return {};
	}

	Log(LogLevel::Info, fmt::format("Opened {} socket{} for DNS Service Discovery.", num_sockets, num_sockets > 1 ? "s" : ""));
	Log(LogLevel::Info, "Sending DNS-SD discovery.");

	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_discovery_send(sockets[isock])) {
			Log(LogLevel::Info, fmt::format("Failed to send DNS-DS discovery: {}", strerror(errno)));
        }
	}

	std::vector<Record> recordsOut;
    std::array<uint8_t, 2048> buffer;
	size_t num_records; // I have no idea what this is for as it does not 

	// This is a simple implementation that loops for <timeout> seconds or as long as we get replies
	int numberOfReadyDescriptors;
	Log(LogLevel::Info, "Reading DNS-SD replies.");
	do {
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 5000; // With ~1ms, it can still sometimes miss some?

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		num_records = 0;
		numberOfReadyDescriptors = select(nfds, &readfs, nullptr, nullptr, &timeout);
		if (numberOfReadyDescriptors > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					mdns_cpp::Record record;
					num_records += mdns_discovery_recv(sockets[isock], buffer.data(), buffer.size(), QueryCallback,
					                               &record);

					recordsOut.push_back(record);
					Log(LogLevel::Debug, fmt::format("Got record: {}", record));
				}
			}
		}
		Log(LogLevel::Debug, fmt::format("Got {} records", num_records));
	} while (numberOfReadyDescriptors > 0);

	for (int isock = 0; isock < num_sockets; ++isock) {
		mdns_socket_close(sockets[isock]);
    }
	Log(LogLevel::Debug, "Closed sockets.");

    return recordsOut;
}   

}