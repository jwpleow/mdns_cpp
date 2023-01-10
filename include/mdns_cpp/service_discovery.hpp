#pragma once

#include <memory>
#include <vector>

#include "mdns_cpp/types.hpp"

namespace mdns_cpp
{

// DNS-SD
std::vector<Record> RunServiceDiscovery();

}