#pragma once

#include <memory>
#include <vector>

#include "mdns_cpp/types.hpp"

namespace mdns_cpp
{

// DNS-SD
// Note: might return repeated records
// This function does take a while to run (1-2s)
std::vector<Record> RunServiceDiscovery();

}