#include "mdns_cpp/types.hpp"

#include <fmt/core.h>
#include <fmt/ostream.h>
#include <fmt/ranges.h>


namespace mdns_cpp
{

std::string ToString(EntryType entry)
{
    switch (entry) {
        case EntryType::QUESTION: return "question";
        case EntryType::ANSWER: return "answer";
        case EntryType::AUTHORITY: return "authority";
        case EntryType::ADDITIONAL: return "additional";
    }
    return "";
}

bool operator==(const RecordHeader& lhs, const RecordHeader& rhs)
{
    return lhs.ip_address == rhs.ip_address
        && lhs.entry_type == rhs.entry_type
        && lhs.entry_string == rhs.entry_string
        && lhs.record_type == rhs.record_type
        && lhs.rclass == rhs.rclass
        && lhs.ttl == rhs.ttl
        && lhs.record_length == rhs.record_length;
}

std::ostream& operator<<(std::ostream& os, const RecordHeader& header)
{
    os << fmt::format("{} : {} {}", header.ip_address, ToString(header.entry_type), header.entry_string);
    return os;
}

bool operator==(const DomainNamePointerRecord& lhs, const DomainNamePointerRecord& rhs)
{
    return lhs.header == rhs.header
        && lhs.name_string == rhs.name_string;
}

std::ostream& operator<<(std::ostream& os, const DomainNamePointerRecord& record)
{
    // Original print statement from mdns.c
    //  printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
    //        MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
    //        MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
    os << fmt::format("{} PTR {} rclass {:#x} ttl {} length {}", record.header, record.name_string, record.header.rclass, record.header.ttl, record.header.record_length);
    return os;
}

bool operator==(const ServiceRecord& lhs, const ServiceRecord& rhs)
{
    return lhs.header == rhs.header
        && lhs.service_name == rhs.service_name
        && lhs.priority == rhs.priority
        && lhs.weight == rhs.weight
        && lhs.port == rhs.port;
}

std::ostream& operator<<(std::ostream& os, const ServiceRecord& record)
{
    // printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
    //        MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
    //        MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    os << fmt::format("{} SRV {} priority {} weight {} port {}", record.header, record.service_name, record.priority, record.weight, record.port);
    return os;
}

bool operator==(const ARecord& lhs, const ARecord& rhs)
{
    return lhs.header == rhs.header
        && lhs.address_string == rhs.address_string;
}

std::ostream& operator<<(std::ostream& os, const ARecord& record)
{
    // printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
    //        MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
    os << fmt::format("{} A {}", record.header, record.address_string);
    return os;
}

bool operator==(const AAAARecord& lhs, const AAAARecord& rhs)
{
    return lhs.header == rhs.header
        && lhs.address_string == rhs.address_string;
}

std::ostream& operator<<(std::ostream& os, const AAAARecord& record)
{
    // printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
    //        MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
    os << fmt::format("{} AAAA {}", record.header, record.address_string);
    return os;
}

bool operator==(const TXTRecord& lhs, const TXTRecord& rhs)
{
    return lhs.header == rhs.header
        && lhs.txt == rhs.txt;
}

std::ostream& operator<<(std::ostream& os, const TXTRecord& record)
{
    // printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
    //        entrytype, MDNS_STRING_FORMAT(entrystr),
    //        MDNS_STRING_FORMAT(txtbuffer[itxt].key),
    //        MDNS_STRING_FORMAT(txtbuffer[itxt].value));
    // TODO: improve this
    os << fmt::format("{} TXT {}", record.header, record.txt);
    return os;
}

bool operator==(const AnyRecord& lhs, const AnyRecord& rhs)
{
    return lhs.header == rhs.header;
}

std::ostream& operator<<(std::ostream& os, const AnyRecord& record)
{
    // printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
    //        MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
    //        rclass, ttl, (int)record_length);
    os << fmt::format("{} type {} rclass {:#x} ttl {} length {}", record.header, record.header.record_type, record.header.rclass, record.header.ttl, record.header.record_length);
    return os; 
}

std::ostream& operator<<(std::ostream& os, const Record& record)
{
    std::visit([&os](const auto& rec){
        os << rec;
    }, record);
    return os;
}

}