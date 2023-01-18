#pragma once

#include <string>
#include <memory>

namespace mdns_cpp
{


struct ServiceSettings 
{
    std::string service_name{"_http._tcp.local."};
    std::string hostname{"myhost"}; 
    std::uint16_t port{5353};
};


// Wrapper around service_mdns() from mdns.c
// Provides a mDNS service, answering incoming DNS-SD and mDNS queries
class Service
{
public:
    Service(ServiceSettings settings = ServiceSettings());
    ~Service();
    // Not thread safe, call this before Start()
    void SetSettings(ServiceSettings settings);

    void Start();
    void Stop();
    [[nodiscard]] bool Started() const;

private:
    class ServiceImpl;
    std::unique_ptr<ServiceImpl> m_impl;
};



}