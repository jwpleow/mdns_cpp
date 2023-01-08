#include "mdns_cpp/mdns.hpp"

#include <iostream>

int main()
{
    const auto asdf = mdns_cpp::RunServiceDiscovery();

    // mdns_cpp::DiscoverySettings settings;
    // settings.logger_callback = [](mdns_cpp::LogLevel level, std::string&& log) {
    //     std::cout << static_cast<int>(level) << " " << log << "\n";
    // };
    // mdns_cpp::Discovery test(settings);

    return 0;
}