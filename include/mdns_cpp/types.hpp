#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <iostream>
#include <vector>
#include <utility>
#include <variant>

namespace mdns_cpp
{

// From mdns.h mdns_record_type
enum class RecordType {
    PTR = 12, // Domain name pointer
    SRV = 33, // Server Selection [RFC2782]
    TXT = 16, // Arbitrary text string
    A = 1, // Address
    AAAA = 28, // IP6 Address [Thomson]
    ANY = 255 // Any available records
};

enum class EntryType {
    UNKNOWN,
    QUESTION,
    ANSWER,
    AUTHORITY,
    ADDITIONAL
};
std::string ToString(EntryType entry);

struct RecordHeader {
    std::string ip_address; // Possibly including port 
    EntryType entry_type;
    std::string entry_string; // example: "_services._dns-sd._udp.local."

    std::uint16_t record_type; // Value may not be in RecordType!
    std::uint16_t rclass;
    std::uint32_t ttl; // Time interval (in seconds?) that the RR should be cached
    std::size_t record_length;
};
bool operator==(const RecordHeader& lhs, const RecordHeader& rhs);
std::ostream& operator<<(std::ostream& os, const RecordHeader& header);

struct DomainNamePointerRecord {
    RecordHeader header;

    std::string name_string; // examples: "_http._tcp.local.", "_teamviewer._tcp.local."
};
bool operator==(const DomainNamePointerRecord& lhs, const DomainNamePointerRecord& rhs);
std::ostream& operator<<(std::ostream& os, const DomainNamePointerRecord& record);

struct ServiceRecord {
    RecordHeader header;

    std::string service_name;
    std::uint16_t priority;
	std::uint16_t weight;
	std::uint16_t port;
};
bool operator==(const ServiceRecord& lhs, const ServiceRecord& rhs);
std::ostream& operator<<(std::ostream& os, const ServiceRecord& record);

struct ARecord {
    RecordHeader header;

    std::string address_string;
};
bool operator==(const ARecord& lhs, const ARecord& rhs);
std::ostream& operator<<(std::ostream& os, const ARecord& record);

struct AAAARecord {
    RecordHeader header;

    std::string address_string;
};
bool operator==(const AAAARecord& lhs, const AAAARecord& rhs);
std::ostream& operator<<(std::ostream& os, const AAAARecord& record);

struct TXTRecord {
    RecordHeader header;

    // Can keys be repeated? Should I just use an unordered_map?
    std::vector<std::pair<std::string, std::string>> txt;
};
bool operator==(const TXTRecord& lhs, const TXTRecord& rhs);
std::ostream& operator<<(std::ostream& os, const TXTRecord& record);

struct AnyRecord {
    RecordHeader header;
};
bool operator==(const AnyRecord& lhs, const AnyRecord& rhs);
std::ostream& operator<<(std::ostream& os, const AnyRecord& record);

using Record = std::variant<DomainNamePointerRecord,
                            ServiceRecord,
                            ARecord,
                            AAAARecord,
                            TXTRecord,
                            AnyRecord>;
std::ostream& operator<<(std::ostream& os, const Record& record);


}