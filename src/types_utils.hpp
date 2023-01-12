#pragma once

#include "mdns_cpp/types.hpp"
#include "mdns.h"

#include <string_view>

namespace mdns_cpp
{

inline mdns_string_t Convert(std::string_view str) {
    return mdns_string_t{str.data(), str.size()};
}

inline mdns_record_t Convert(const DomainNamePointerRecord& record)
{
    // // PTR record reverse mapping "<_service-name>._tcp.local." to
    // // "<hostname>.<_service-name>._tcp.local."
    // service.record_ptr = (mdns_record_t){.name = service.service,
    //                                      .type = MDNS_RECORDTYPE_PTR,
    //                                      .data.ptr.name = service.service_instance,
    //                                      .rclass = 0,
    //                                      .ttl = 0};
    mdns_record_t recordOut;
    recordOut.name = Convert(record.header.entry_string);
    recordOut.type = MDNS_RECORDTYPE_PTR;
    recordOut.data.ptr.name = Convert(record.name_string);

    recordOut.rclass = record.header.rclass;
    recordOut.ttl = record.header.ttl;
    return recordOut;
}

inline mdns_record_t Convert(const ServiceRecord& record)
{
    // // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
    // // "<hostname>.local." with port. Set weight & priority to 0.
    // service.record_srv = (mdns_record_t){.name = service.service_instance,
    //                                      .type = MDNS_RECORDTYPE_SRV,
    //                                      .data.srv.name = service.hostname_qualified,
    //                                      .data.srv.port = service.port,
    //                                      .data.srv.priority = 0,
    //                                      .data.srv.weight = 0,
    //                                      .rclass = 0,
    //                                      .ttl = 0};
    mdns_record_t recordOut;
    recordOut.name = Convert(record.header.entry_string);
    recordOut.type = MDNS_RECORDTYPE_SRV;
    recordOut.data.srv.name = Convert(record.service_name);
    recordOut.data.srv.port = record.port;
    recordOut.data.srv.priority = record.priority;
    recordOut.data.srv.weight = record.weight;

    recordOut.rclass = record.header.rclass;
    recordOut.ttl = record.header.ttl;
    return recordOut;
}


inline mdns_record_t Convert(const ARecord& record)
{
    // // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
    // service.record_a = (mdns_record_t){.name = service.hostname_qualified,
    //                                    .type = MDNS_RECORDTYPE_A,
    //                                    .data.a.addr = service.address_ipv4,
    //                                    .rclass = 0,
    //                                    .ttl = 0};
    mdns_record_t recordOut;
    recordOut.name = Convert(record.header.entry_string);
    recordOut.type = MDNS_RECORDTYPE_A;
    // recordOut.data.a.addr = Convert(record.address_string);

    recordOut.rclass = record.header.rclass;
    recordOut.ttl = record.header.ttl;
    return recordOut;
}

inline mdns_record_t Convert(const AAAARecord& record)
{
    // // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
    // service.record_a = (mdns_record_t){.name = service.hostname_qualified,
    //                                    .type = MDNS_RECORDTYPE_A,
    //                                    .data.a.addr = service.address_ipv4,
    //                                    .rclass = 0,
    //                                    .ttl = 0};
    mdns_record_t recordOut;
    recordOut.name = Convert(record.header.entry_string);
    recordOut.type = MDNS_RECORDTYPE_AAAA;
    // recordOut.data.a.addr = service.address;

    recordOut.rclass = record.header.rclass;
    recordOut.ttl = record.header.ttl;
    return recordOut;
}

inline std::vector<mdns_record_t> Convert(const TXTRecord& recordIn)
{
    // // Add two test TXT records for our service instance name, will be coalesced into
    // // one record with both key-value pair strings by the library
    // service.txt_record[0] = (mdns_record_t){.name = service.service_instance,
    //                                         .type = MDNS_RECORDTYPE_TXT,
    //                                         .data.txt.key = {MDNS_STRING_CONST("test")},
    //                                         .data.txt.value = {MDNS_STRING_CONST("1")},
    //                                         .rclass = 0,
    //                                         .ttl = 0};
    std::vector<mdns_record_t> recordsOut;
    for (const auto& txtpair : recordIn.txt) {
        mdns_record_t rec;
        rec.name = Convert(recordIn.header.entry_string);
        rec.type = MDNS_RECORDTYPE_TXT;
        rec.data.txt.key = Convert(txtpair.first);
        rec.data.txt.value = Convert(txtpair.second);
        rec.rclass = recordIn.header.rclass;
        rec.ttl = recordIn.header.ttl;
    }

    return recordsOut;
}


}