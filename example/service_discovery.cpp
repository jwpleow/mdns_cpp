#include "mdns_cpp/service_discovery.hpp"

#include <iostream>

int main()
{
    const auto records = mdns_cpp::RunServiceDiscovery();
    std::cout << "Got " << records.size() << " records.\n";
    for (const auto& record : records) {
        std::cout << record << "\n";
    }

    return 0;
}