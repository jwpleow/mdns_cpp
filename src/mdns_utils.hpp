#pragma once

#include "mdns.h"
#include "mdns_cpp/types.hpp"

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

mdns_cpp::EntryType ParseEntryType(mdns_entry_type old_entry_type) {
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

inline std::vector<int> OpenClientSockets(int port) {
    std::vector<int> sockets;
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
    struct sockaddr_in service_address_ipv4;
	struct sockaddr_in6 service_address_ipv6;

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
						service_address_ipv4 = *saddr;
						first_ipv4 = 0;
						log_addr = 1;
					}
					has_ipv4 = 1;
			
                    saddr->sin_port = htons((unsigned short)port);
                    int sock = mdns_socket_open_ipv4(saddr);
                    if (sock >= 0) {
                        sockets.push_back(sock);
                        log_addr = 1;
                    } else {
                        log_addr = 0;
                    }
			
					if (log_addr) {
						const auto addr = IPV4AddressToString(saddr, sizeof(struct sockaddr_in));
                        Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
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
						service_address_ipv6 = *saddr;
						first_ipv6 = 0;
						log_addr = 1;
					}
					has_ipv6 = 1;
	
                    saddr->sin6_port = htons((unsigned short)port);
                    int sock = mdns_socket_open_ipv6(saddr);
                    if (sock >= 0) {
                        sockets.push_back(sock);
                        log_addr = 1;
                    } else {
                        log_addr = 0;
                    }
			
					if (log_addr) {
						const auto addr = IPV6AddressToString(saddr, sizeof(struct sockaddr_in6));
						Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
					}
				}
			}
		}
	}


#else

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

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
					service_address_ipv4 = *saddr;
					first_ipv4 = 0;
					log_addr = 1;
				}
				has_ipv4 = 1;
                saddr->sin_port = htons(port);
                int sock = mdns_socket_open_ipv4(saddr);
                if (sock >= 0) {
                    sockets.push_back(sock);
                    log_addr = 1;
                } else {
                    log_addr = 0;
                }
				if (log_addr) {
                    const auto addr = IPV4AddressToString(saddr, sizeof(struct sockaddr_in));
                    Log(LogLevel::Debug, "Socket opened for interface with local IPv4 address: " + addr);
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
					service_address_ipv6 = *saddr;
					first_ipv6 = 0;
					log_addr = 1;
				}
				has_ipv6 = 1;

                saddr->sin6_port = htons(port);
                int sock = mdns_socket_open_ipv6(saddr);
                if (sock >= 0) {
                    sockets.push_back(sock);
                    log_addr = 1;
                } else {
                    log_addr = 0;
                }
	
				if (log_addr) {
					const auto addr = IPV6AddressToString(saddr, sizeof(struct sockaddr_in6));
                    Log(LogLevel::Debug, "Socket opened for interface with local IPv6 address: " + addr);
				}
			}
		}
	}

	freeifaddrs(ifaddr);

#endif
    return sockets;
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




}