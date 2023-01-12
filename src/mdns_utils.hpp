#pragma once

#include "mdns.h"
#include "mdns_cpp/types.hpp"
#include "types_utils.hpp"

#include <functional>
#include <string>
#include <memory>
#include <vector>

#include "log.hpp"

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock.h>
#else
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <fmt/core.h>

namespace mdns_cpp
{

// 99% of the code below are copypasta from mdns.c

enum
{
    IFF_UP = 0x1,		/* Interface is up.  */
# define IFF_UP	IFF_UP
    IFF_BROADCAST = 0x2,	/* Broadcast address valid.  */
# define IFF_BROADCAST	IFF_BROADCAST
    IFF_DEBUG = 0x4,		/* Turn on debugging.  */
# define IFF_DEBUG	IFF_DEBUG
    IFF_LOOPBACK = 0x8,		/* Is a loopback net.  */
# define IFF_LOOPBACK	IFF_LOOPBACK
    IFF_POINTOPOINT = 0x10,	/* Interface is point-to-point link.  */
# define IFF_POINTOPOINT IFF_POINTOPOINT
    IFF_NOTRAILERS = 0x20,	/* Avoid use of trailers.  */
# define IFF_NOTRAILERS	IFF_NOTRAILERS
    IFF_RUNNING = 0x40,		/* Resources allocated.  */
# define IFF_RUNNING	IFF_RUNNING
    IFF_NOARP = 0x80,		/* No address resolution protocol.  */
# define IFF_NOARP	IFF_NOARP
    IFF_PROMISC = 0x100,	/* Receive all packets.  */
# define IFF_PROMISC	IFF_PROMISC

    /* Not supported */
    IFF_ALLMULTI = 0x200,	/* Receive all multicast packets.  */
# define IFF_ALLMULTI	IFF_ALLMULTI

    IFF_MASTER = 0x400,		/* Master of a load balancer.  */
# define IFF_MASTER	IFF_MASTER
    IFF_SLAVE = 0x800,		/* Slave of a load balancer.  */
# define IFF_SLAVE	IFF_SLAVE

    IFF_MULTICAST = 0x1000,	/* Supports multicast.  */
# define IFF_MULTICAST	IFF_MULTICAST

    IFF_PORTSEL = 0x2000,	/* Can set media type.  */
# define IFF_PORTSEL	IFF_PORTSEL
    IFF_AUTOMEDIA = 0x4000,	/* Auto media select active.  */
# define IFF_AUTOMEDIA	IFF_AUTOMEDIA
    IFF_DYNAMIC = 0x8000	/* Dialup device with changing addresses.  */
# define IFF_DYNAMIC	IFF_DYNAMIC
};

struct service_t {
	mdns_string_t service;
	mdns_string_t hostname;
	mdns_string_t service_instance;
	mdns_string_t hostname_qualified;
	struct sockaddr_in address_ipv4;
	struct sockaddr_in6 address_ipv6;
	int port;

	mdns_record_t record_ptr;
	mdns_record_t record_srv;
	mdns_record_t record_a;
	mdns_record_t record_aaaa;
	std::vector<mdns_record_t> txt_records;
};

inline mdns_cpp::EntryType ParseEntryType(mdns_entry_type old_entry_type) {
	switch (old_entry_type) {
		case MDNS_ENTRYTYPE_QUESTION : return EntryType::QUESTION;
		case MDNS_ENTRYTYPE_ANSWER : return EntryType::ANSWER;
		case MDNS_ENTRYTYPE_AUTHORITY : return EntryType::AUTHORITY;
		case MDNS_ENTRYTYPE_ADDITIONAL : return EntryType::ADDITIONAL;
	}
	return EntryType::UNKNOWN;
}

inline std::string IPV4AddressToString(const sockaddr_in *addr, size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  const int ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
  if (ret == 0) {
    if (addr->sin_port != 0) {
	  return fmt::format("{}:{}", host, service);
    } else {
	  return fmt::format("{}", host);
    }
  }
  return "";
}

inline std::string IPV6AddressToString(const sockaddr_in6 *addr, size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  const int ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
  if (ret == 0) {
    if (addr->sin6_port != 0) {
	  return fmt::format("[{}]:{}", host, service);
    } else {
	  return fmt::format("{}", host);
    }
  }
  return "";
}

inline std::string IPAddressToString(const sockaddr *addr, size_t addrlen) {
  if (addr->sa_family == AF_INET6) {
    return IPV6AddressToString((const struct sockaddr_in6 *)addr, addrlen);
  }
  return IPV4AddressToString((const struct sockaddr_in *)addr, addrlen);
}

struct OpenSocketsData {
	std::vector<int> sockets;
	struct sockaddr_in service_address_ipv4;
	struct sockaddr_in6 service_address_ipv6;
};

inline OpenSocketsData OpenClientSockets(int port, std::size_t max_sockets = 64) {
    OpenSocketsData returnData;
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family

	int has_ipv4;
	int has_ipv6;
#ifdef _WIN32
    auto adapter_address = std::make_unique<IP_ADAPTER_ADDRESSES>();
	ULONG address_size = 8000;
	unsigned int ret;
	unsigned int num_retries = 4;
	do {
		adapter_address = (IP_ADAPTER_ADDRESSES*)malloc(address_size);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
		                           adapter_address.get(), &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			adapter_address.reset();
			address_size *= 2;
		} else {
			break;
		}
	} while (num_retries-- > 0);

	if (!adapter_address || (ret != NO_ERROR)) {
        adapter_address.reset();
		Log(LogLevel::Warn, "Failed to get network adapter addresses");
		return num_sockets;
	}

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (PIP_ADAPTER_ADDRESSES adapter = adapter_address.get(); adapter; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
		     unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
				if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
					int log_addr = 0;
					if (first_ipv4) {
						returnData.service_address_ipv4 = *saddr;
						first_ipv4 = 0;
						log_addr = 1;
					}
					has_ipv4 = 1;
					if (sockets.size() < max_sockets) {
						saddr->sin_port = htons((unsigned short)port);
						int sock = mdns_socket_open_ipv4(saddr);
						if (sock >= 0) {
							returnData.sockets.push_back(sock);
							log_addr = 1;
							const auto addr = IPV4AddressToString(saddr, sizeof(struct sockaddr_in));
                        	Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
						} else {
							log_addr = 0;
						}
					}
				}
			} else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
				struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
				// Ignore link-local addresses
				if (saddr->sin6_scope_id)
					continue;
				const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
				                                          0, 0, 0, 0, 0, 0, 0, 1};
				const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
				                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
				if ((unicast->DadState == NldsPreferred) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
					int log_addr = 0;
					if (first_ipv6) {
						returnData.service_address_ipv6 = *saddr;
						first_ipv6 = 0;
						log_addr = 1;
					}
					has_ipv6 = 1;
					if (sockets.size() < max_sockets) {
						saddr->sin6_port = htons((unsigned short)port);
						int sock = mdns_socket_open_ipv6(saddr);
						if (sock >= 0) {
							returnData.sockets.push_back(sock);
							log_addr = 1;
							const auto addr = IPV6AddressToString(saddr, sizeof(struct sockaddr_in6));
							Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
						} else {
							log_addr = 0;
						}
					}
				}
			}
		}
	}


#else

	struct ifaddrs* ifaddr = nullptr;
	struct ifaddrs* ifa = nullptr;

	if (getifaddrs(&ifaddr) < 0) {
		Log(LogLevel::Warn, "Unable to get interface addresses");
    }

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
			continue;
		if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
				int log_addr = 0;
				if (first_ipv4) {
					returnData.service_address_ipv4 = *saddr;
					first_ipv4 = 0;
					log_addr = 1;
				}
				has_ipv4 = 1;
				if (returnData.sockets.size() < max_sockets) {
					saddr->sin_port = htons(port);
					int sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) {
						returnData.sockets.push_back(sock);
						log_addr = 1;
						const auto addr = IPV4AddressToString(saddr, sizeof(struct sockaddr_in));
                    	Log(LogLevel::Debug, "Socket opened for interface with local IPv4 address: " + addr);
					} else {
						log_addr = 0;
					}
				}
			}
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6* saddr = (struct sockaddr_in6*)ifa->ifa_addr;
			// Ignore link-local addresses
			if (saddr->sin6_scope_id)
				continue;
			const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
			                                          0, 0, 0, 0, 0, 0, 0, 1};
			const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
			                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
			if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
			    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
				int log_addr = 0;
				if (first_ipv6) {
					returnData.service_address_ipv6 = *saddr;
					first_ipv6 = 0;
					log_addr = 1;
				}
				has_ipv6 = 1;
				if (returnData.sockets.size() < max_sockets) {
					saddr->sin6_port = htons(port);
					int sock = mdns_socket_open_ipv6(saddr);
					if (sock >= 0) {
						returnData.sockets.push_back(sock);
						log_addr = 1;
						const auto addr = IPV6AddressToString(saddr, sizeof(struct sockaddr_in6));
                    	Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
					} else {
						log_addr = 0;
					}
				}
			}
		}
	}

	freeifaddrs(ifaddr);

#endif
    return returnData;
}

inline OpenSocketsData OpenServiceSockets() {
	// When receiving, each socket can receive data from all network interfaces
	// Thus we only need to open one socket for each address family

	// Call the client socket function to enumerate and get local addresses,
	// but not open the actual sockets
	auto openSocketData = OpenClientSockets(0, 0);

	/// IPv4
	{
		struct sockaddr_in sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in));
		sock_addr.sin_family = AF_INET;
#ifdef _WIN32
		sock_addr.sin_addr = in4addr_any;
#else
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
		sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
		int sock = mdns_socket_open_ipv4(&sock_addr);
		if (sock >= 0) {
			openSocketData.sockets.push_back(sock);
		}
	}

	/// IPv6
	{
		struct sockaddr_in6 sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
		sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
		int sock = mdns_socket_open_ipv6(&sock_addr);
		if (sock >= 0) {
			openSocketData.sockets.push_back(sock);
		}
	}

	return openSocketData;
}

inline int QueryCallback(int sock, const struct sockaddr* from, size_t addrlen,
                        mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
                        uint16_t rclass, uint32_t ttl, const void* data, size_t size,
                        size_t name_offset, size_t name_length, size_t record_offset,
                        size_t record_length, void* user_data)
{
    auto recordOut = reinterpret_cast<Record*>(user_data);
	RecordHeader header;
    header.ip_address = IPAddressToString(from, addrlen);
    header.entry_type = ParseEntryType(entry);
    char entrybuffer[256];
    // entrystr example: "_services._dns-sd._udp.local."
    const mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
    header.entry_string = std::string(entrystr.str, entrystr.length);
	header.record_type = rtype;
	header.rclass = rclass;
	header.ttl = ttl;
	header.record_length = record_length;

    if (rtype == MDNS_RECORDTYPE_PTR) {
		auto domainPtrRecord = DomainNamePointerRecord();
		domainPtrRecord.header = std::move(header);

        char namebuffer[256];
		const mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));

		domainPtrRecord.name_string = std::string(namestr.str, namestr.length);
		*recordOut = std::move(domainPtrRecord);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		auto srvRecord = ServiceRecord();
		srvRecord.header = std::move(header);

        char namebuffer[256];
		const mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));
		srvRecord.service_name = std::string(srv.name.str, srv.name.length);

		*recordOut = std::move(srvRecord);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		auto aRecord = ARecord();
		aRecord.header = std::move(header);

		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		aRecord.address_string = IPV4AddressToString(&addr, sizeof(addr));

		*recordOut = std::move(aRecord);
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		auto aaaaRecord = AAAARecord();
		aaaaRecord.header = std::move(header);

		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
        aaaaRecord.address_string = IPV6AddressToString(&addr, sizeof(addr));

		*recordOut = std::move(aaaaRecord);
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		auto txtRecord = TXTRecord();
		txtRecord.header = std::move(header);

        mdns_record_txt_t txtbuffer[128];
		const size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
		                                      sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
            const std::string key = std::string(txtbuffer[itxt].key.str, txtbuffer[itxt].key.length);
            const std::string value = std::string(txtbuffer[itxt].value.str, txtbuffer[itxt].value.length);

			txtRecord.txt.emplace_back(key, value);
		}
	} else {
		auto anyRecord = AnyRecord();
		anyRecord.header = std::move(header);
	}

    return 0;
}   


// Callback handling questions incoming on service sockets
inline int ServiceCallback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
                 size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                 size_t record_length, void* user_data) {
	if (entry != MDNS_ENTRYTYPE_QUESTION) {
		return 0;
	}

	const char dns_sd[] = "_services._dns-sd._udp.local.";
	const service_t* service = (const service_t*)user_data;

	const std::string fromaddrstr_ = IPAddressToString(from, addrlen);
	mdns_string_t fromaddrstr = Convert(fromaddrstr_);

	char namebuffer[256];
	size_t offset = name_offset;
	mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

	std::string record_name;
	mdns_record_type record_type;
	if (rtype == MDNS_RECORDTYPE_PTR) {
		record_name = "PTR";
		record_type = MDNS_RECORDTYPE_PTR;
	}
	else if (rtype == MDNS_RECORDTYPE_SRV) {
		record_name = "SRV";
		record_type = MDNS_RECORDTYPE_SRV;
	}
	else if (rtype == MDNS_RECORDTYPE_A) {
		record_name = "A";
		record_type = MDNS_RECORDTYPE_A;
	}
	else if (rtype == MDNS_RECORDTYPE_AAAA) {
		record_name = "AAAA";
		record_type = MDNS_RECORDTYPE_AAAA;
	}
	else if (rtype == MDNS_RECORDTYPE_TXT) {
		record_name = "TXT";
		record_type = MDNS_RECORDTYPE_TXT;
	}
	else if (rtype == MDNS_RECORDTYPE_ANY) {
		record_name = "ANY";
		record_type = MDNS_RECORDTYPE_ANY;
	}
	else
		return 0;

	Log(LogLevel::Info, fmt::format("Query {} {}", record_name, std::string(name.str, name.length)));

	std::array<char, 1024> sendbuffer;
	if ((name.length == (sizeof(dns_sd) - 1)) &&
	    (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for the DNS-SD domain, send answer with a PTR record for the
			// service name we advertise, typically on the "<_service-name>._tcp.local." format

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer;
			answer.name = name;
			answer.type = MDNS_RECORDTYPE_PTR;
			answer.data.ptr.name = service->service;

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			Log(LogLevel::Info, fmt::format("  --> answer {} ({})", std::string(answer.data.ptr.name.str, answer.data.ptr.name.length), (unicast ? "unicast" : "multicast")));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer.data(), sendbuffer.size(),
				                          query_id, record_type, name.str, name.length, answer, 0, 0, 0,
				                          0);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer.data(), sendbuffer.size(), answer, 0, 0, 0, 0);
			}
		}
	} else if ((name.length == service->service.length) &&
	           (strncmp(name.str, service->service.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
			// record reverse mapping the queried service name to our service instance name
			// (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
			// additional records containing the SRV record mapping the service instance name to our
			// qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
			// address for the hostname as A/AAAA records, and two test TXT records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer = service->record_ptr;

			std::vector<mdns_record_t> additional;

			// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
			// "<hostname>.local." with port. Set weight & priority to 0.
			additional.push_back(service->record_srv);

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional.push_back(service->record_a);
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional.push_back(service->record_aaaa);

			// Add TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional.insert(additional.end(), service->txt_records.begin(), service->txt_records.end());

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			Log(LogLevel::Info, fmt::format("  --> answer {} ({})", std::string(service->record_ptr.data.ptr.name.str, service->record_ptr.data.ptr.name.length), (unicast ? "unicast" : "multicast")));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer.data(), sendbuffer.size(),
				                          query_id, record_type, name.str, name.length, answer, 0, 0,
				                          additional.data(), additional.size());
			} else {
				mdns_query_answer_multicast(sock, sendbuffer.data(), sendbuffer.size(), answer, 0, 0,
				                            additional.data(), additional.size());
			}
		}
	} else if ((name.length == service->service_instance.length) &&
	           (strncmp(name.str, service->service_instance.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The SRV query was for our service instance (usually
			// "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
			// instance name to our qualified hostname (typically "<hostname>.local.") and port, as
			// well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
			// records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer = service->record_srv;

			std::vector<mdns_record_t> additional;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional.push_back(service->record_a);
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional.push_back(service->record_aaaa);

			// Add TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional.insert(additional.end(), service->txt_records.begin(), service->txt_records.end());

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			Log(LogLevel::Info, fmt::format("  --> answer {} port {} ({})", std::string(service->record_srv.data.srv.name.str, service->record_srv.data.srv.name.length), service->port, (unicast ? "unicast" : "multicast")));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer.data(), sendbuffer.size(),
				                          query_id, record_type, name.str, name.length, answer, 0, 0,
				                          additional.data(), additional.size());
			} else {
				mdns_query_answer_multicast(sock, sendbuffer.data(), sendbuffer.size(), answer, 0, 0,
				                            additional.data(), additional.size());
			}
		}
	} else if ((name.length == service->hostname_qualified.length) &&
	           (strncmp(name.str, service->hostname_qualified.str, name.length) == 0)) {
		if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		    (service->address_ipv4.sin_family == AF_INET)) {
			// The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
			mdns_record_t answer = service->record_a;

			std::vector<mdns_record_t> additional;

			// AAAA record mapping "<hostname>.local." to IPv6 addresses
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional.push_back(service->record_aaaa);

			// Add TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional.insert(additional.end(), service->txt_records.begin(), service->txt_records.end());

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			std::string addrstr_cpp = IPAddressToString((struct sockaddr*)&service->record_a.data.a.addr,
			    sizeof(service->record_a.data.a.addr));
			mdns_string_t addrstr = Convert(addrstr_cpp);

			Log(LogLevel::Info, fmt::format("  --> answer  {} IPv4 {} ({})", std::string(service->record_a.name.str, service->record_a.name.length), addrstr_cpp, (unicast ? "unicast" : "multicast")));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer.data(), sendbuffer.size(),
				                          query_id, record_type, name.str, name.length, answer, 0, 0,
				                          additional.data(), additional.size());
			} else {
				mdns_query_answer_multicast(sock, sendbuffer.data(), sendbuffer.size(), answer, 0, 0,
				                            additional.data(), additional.size());
			}
		} else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		           (service->address_ipv6.sin6_family == AF_INET6)) {
			// The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
			mdns_record_t answer = service->record_aaaa;

			std::vector<mdns_record_t> additional;

			// A record mapping "<hostname>.local." to IPv4 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional.push_back(service->record_a);

			// Add TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional.insert(additional.end(), service->txt_records.begin(), service->txt_records.end());

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);

			std::string addrstr_cpp = IPAddressToString((struct sockaddr*)&service->record_aaaa.data.aaaa.addr,
			    sizeof(service->record_aaaa.data.aaaa.addr));

			mdns_string_t addrstr = Convert(addrstr_cpp);
			
			Log(LogLevel::Info, fmt::format("  --> answer  {} IPv6 {} ({})", std::string(service->record_aaaa.name.str, service->record_aaaa.name.length), addrstr_cpp, (unicast ? "unicast" : "multicast")));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer.data(), sendbuffer.size(),
				                          query_id, record_type, name.str, name.length, answer, 0, 0,
				                          additional.data(), additional.size());
			} else {
				mdns_query_answer_multicast(sock, sendbuffer.data(), sendbuffer.size(), answer, 0, 0,
				                            additional.data(), additional.size());
			}
		}
	}
	return 0;
}


}