#pragma once

#include <string>
#include <memory>

namespace mdns_cpp
{


struct Service 
{
    std::string service_name{"_http._tcp.local."};
    std::string hostname{"myhost"}; 
    std::uint16_t port{5353};
};


// Wrapper around service_mdns() from mdns.c
// Provides a mDNS service, answering incoming DNS-SD and mDNS queries
class mDNSService
{
public:
    mDNSService(Service service);
    ~mDNSService();

    void Start();
    void Stop();

private:
    class ServiceImpl;
    std::unique_ptr<ServiceImpl> m_impl;
};



}