#pragma once

#include <memory>
#include <vector>

#include "mdns_cpp/types.hpp"

namespace mdns_cpp
{

// DNS-SD
std::vector<Record> RunServiceDiscovery();

// struct DiscoverySettings
// {
//     LoggerCallback logger_callback;

// };

// class Discovery
// {
// public:
//     Discovery(DiscoverySettings settings = {});
//     ~Discovery();

// private:
//     class DiscoveryImpl;
//     std::unique_ptr<DiscoveryImpl> m_impl;

// };


}