#include "mdns_cpp/service.hpp"

#include <chrono>
#include <thread>

int main()
{
    mdns_cpp::ServiceSettings srv;

    mdns_cpp::Service service(srv);

    service.Start();
    std::this_thread::sleep_for(std::chrono::seconds(2000));
    service.Stop();
    
    return 0;
}