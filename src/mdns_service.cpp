#include "mdns_cpp/mdns_service.hpp"
#include "mdns_cpp/types.hpp"
#include "mdns_utils.hpp"
#include "types_utils.hpp"

#include <atomic>
#include <thread>
#include <array>

#include "log.hpp"
#include <fmt/format.h>

namespace mdns_cpp
{

struct ServiceData
{
	std::string service;
	std::string hostname;
	std::string service_instance;
	std::string hostname_qualified;
	OpenSocketsData sockets_data;
	int port;

	DomainNamePointerRecord record_ptr;
	ServiceRecord record_service;
	ARecord record_a;
	AAAARecord record_aaaa;
	std::vector<mdns_record_t> txt_records;
};

class mDNSService::ServiceImpl
{
private:
	ServiceData m_serviceData;
	service_t m_serviceDataForMdns;

	std::atomic<bool> m_running{false};
	std::thread m_listenThread;

public:
	ServiceImpl(Service service)
	{
		if (service.service_name.empty()) {
			Log(LogLevel::Error, "Empty service name.");
			throw std::runtime_error("Empty service name.");
		}

		m_serviceData.sockets_data = OpenServiceSockets();
		const auto num_sockets = m_serviceData.sockets_data.sockets.size();
		if (num_sockets == 0) {
			Log(LogLevel::Error, "Failed to open any client sockets.");
			throw std::runtime_error("Failed to open any client sockets.");
		}
		Log(LogLevel::Info, fmt::format("Opened {} socket{} for mDNS Service.", num_sockets, num_sockets > 1 ? "s": ""));


		m_serviceData.port = service.port;
		m_serviceData.hostname = service.hostname;
		m_serviceData.service = service.service_name;
		if (m_serviceData.service.back() != '.') {
			m_serviceData.service += '.';
		}

		Log(LogLevel::Info, fmt::format("Service mDNS: {}:{}", m_serviceData.service, m_serviceData.port));
		Log(LogLevel::Info, fmt::format("Hostname: {}", m_serviceData.hostname));

		// Build the service instance "<hostname>.<_service-name>._tcp.local." string
		m_serviceData.service_instance = fmt::format("{}.{}", m_serviceData.hostname, m_serviceData.service);
		// Build the "<hostname>.local." string
		m_serviceData.hostname_qualified = fmt::format("{}.local.", m_serviceData.hostname);

		// PTR record
		m_serviceData.record_ptr.header.entry_string = m_serviceData.service;
		m_serviceData.record_ptr.name_string = m_serviceData.service_instance;

		// SRV record
		m_serviceData.record_service.header.entry_string = m_serviceData.service_instance;
		m_serviceData.record_service.service_name = m_serviceData.hostname_qualified;
		m_serviceData.record_service.port = m_serviceData.port;
		m_serviceData.record_service.weight = 0;
		m_serviceData.record_service.priority = 0;

		// A/AAAA record
		m_serviceData.record_a.header.entry_string = m_serviceData.hostname_qualified;
		m_serviceData.record_a.address_string = IPV4AddressToString(&m_serviceData.sockets_data.service_address_ipv4, sizeof(struct sockaddr_in));

		m_serviceData.record_aaaa.header.entry_string = m_serviceData.hostname_qualified;
		m_serviceData.record_aaaa.address_string = IPV6AddressToString(&m_serviceData.sockets_data.service_address_ipv6, sizeof(struct sockaddr_in));

		// create data struct for calls to the mdns lib
		m_serviceDataForMdns.service = Convert(m_serviceData.service);
		m_serviceDataForMdns.hostname = Convert(m_serviceData.hostname);
		m_serviceDataForMdns.service_instance = Convert(m_serviceData.service_instance);
		m_serviceDataForMdns.hostname_qualified = Convert(m_serviceData.hostname_qualified);
		m_serviceDataForMdns.address_ipv4 = m_serviceData.sockets_data.service_address_ipv4;
		m_serviceDataForMdns.address_ipv6 = m_serviceData.sockets_data.service_address_ipv6;
		m_serviceDataForMdns.port = m_serviceData.port;

		m_serviceDataForMdns.record_ptr = Convert(m_serviceData.record_ptr);
		m_serviceDataForMdns.record_srv = Convert(m_serviceData.record_service);
		m_serviceDataForMdns.record_a = Convert(m_serviceData.record_a);
		// TODO: Actually convert to/from the address type stored in mdns_cpp::ARecord/AAAARecord
		m_serviceDataForMdns.record_a.data.a.addr = m_serviceData.sockets_data.service_address_ipv4;
		m_serviceDataForMdns.record_aaaa = Convert(m_serviceData.record_aaaa);
		m_serviceDataForMdns.record_aaaa.data.aaaa.addr = m_serviceData.sockets_data.service_address_ipv6;
	}

	~ServiceImpl() {
		Stop();
	}

	void Start()
	{
		Log(LogLevel::Debug, "mDNS Service Start called.");
		if (m_running.exchange(true, std::memory_order_acq_rel) == true) {
			Log(LogLevel::Info, "mDNS Service already started.");
			return;
		}

		// Send an announcement on startup of service
		{
			Log(LogLevel::Info, "mDNS Service sending announce.");
			std::vector<mdns_record_t> additional;
			additional.push_back(m_serviceDataForMdns.record_srv);
			if (m_serviceDataForMdns.address_ipv4.sin_family == AF_INET) {
				additional.push_back(m_serviceDataForMdns.record_a);
			}
			if (m_serviceDataForMdns.address_ipv6.sin6_family == AF_INET6) {
				additional.push_back(m_serviceDataForMdns.record_aaaa);
			}

			std::array<char, 2048> buffer;
			for (std::size_t isock = 0; isock < m_serviceData.sockets_data.sockets.size(); ++isock) {
				mdns_announce_multicast(m_serviceData.sockets_data.sockets[isock], buffer.data(), buffer.size(), m_serviceDataForMdns.record_ptr, 0, 0, additional.data(), additional.size());
			}
		}

		m_listenThread = std::thread([this](){
			ListenLoop();
		});
	}

	void Stop()
	{
		if (m_running.exchange(false, std::memory_order_acq_rel) == false){
			// Was not running previously!
			return;
		}

		Log(LogLevel::Info, "mDNS Service stopping.");

		if (m_listenThread.joinable()) {
			m_listenThread.join();
		}

		// Send a goodbye on end of service
		{
			std::vector<mdns_record_t> additional;
			additional.push_back(m_serviceDataForMdns.record_srv);
			if (m_serviceDataForMdns.address_ipv4.sin_family == AF_INET) {
				additional.push_back(m_serviceDataForMdns.record_a);
			}
			if (m_serviceDataForMdns.address_ipv6.sin6_family == AF_INET6) {
				additional.push_back(m_serviceDataForMdns.record_aaaa);
			}

			std::array<char, 2048> buffer;

			for (std::size_t isock = 0; isock < m_serviceData.sockets_data.sockets.size(); ++isock) {
				mdns_goodbye_multicast(m_serviceData.sockets_data.sockets[isock], buffer.data(), buffer.size(), m_serviceDataForMdns.record_ptr, 0, 0, additional.data(), additional.size());
			}
		}

		for (std::size_t isock = 0; isock < m_serviceData.sockets_data.sockets.size(); ++isock) {
			mdns_socket_close(m_serviceData.sockets_data.sockets[isock]);
		}
		m_serviceData.sockets_data.sockets.clear();

		Log(LogLevel::Info, "DNS service stopped.");
	}

protected:
	void ListenLoop()
	{
		// This is a crude implementation that checks for incoming queries
		while (m_running.load(std::memory_order_acquire)) {
			int nfds = 0;
			fd_set readfs;
			FD_ZERO(&readfs);
			for (const auto& sock : m_serviceData.sockets_data.sockets) {
				if (sock >= nfds)
					nfds = sock + 1;
				FD_SET(sock, &readfs);
			}

			struct timeval timeout;
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000;

			std::array<char, 2048> buffer;
			if (select(nfds, &readfs, nullptr, nullptr, &timeout) >= 0) {
				for (const auto& sock : m_serviceData.sockets_data.sockets) {
					if (FD_ISSET(sock, &readfs)) {
						mdns_socket_listen(sock, buffer.data(), buffer.size(), ServiceCallback,
										&m_serviceDataForMdns);
					}
					FD_SET(sock, &readfs);
				}
			} else {
				break;
			}
		}
	}

};

mDNSService::mDNSService(Service service)
: m_impl(std::make_unique<ServiceImpl>(std::move(service)))
{}

mDNSService::~mDNSService() = default;

void mDNSService::Start()
{
	m_impl->Start();
}

void mDNSService::Stop()
{
	m_impl->Stop();
}




}