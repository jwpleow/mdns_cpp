#include "mdns_cpp/mdns_service.hpp"

#include <chrono>
#include <thread>

int main()
{
    mdns_cpp::Service srv;

    mdns_cpp::mDNSService service(srv);

    service.Start();
    std::this_thread::sleep_for(std::chrono::seconds(20));
    service.Stop();
    
    return 0;
}