#pragma once

#include <memory>
#include <vector>

#include "mdns_cpp/types.hpp"

namespace mdns_cpp
{

// DNS-SD
// Note: might return repeated records
std::vector<Record> RunServiceDiscovery();

}