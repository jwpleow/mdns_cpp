#pragma once

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "log.hpp"

#include <string>
#include <atomic>

namespace mdns_cpp
{

#ifdef _WIN32
// Singleton to help call WSAStartup so that Windows socket calls work
class WinsockManager
{
public:
    // Returns true if successfully initialised/already initialised
    static bool Init() { 
        if (!GetInstance().m_initialised) {
            GetInstance().Startup(); // Try initialising again..?
        }
        return GetInstance().m_initialised; 
    }
private:
    bool Startup() {
        WSADATA wsaData;
        const auto res = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (res != 0) {
            Log(LogLevel::Error, "WSAStartup failed with error code: " + std::to_string(res));
            return false;
        }
        m_initialised = true;
        return true;
    }

    WinsockManager() {
        Startup();
    }

    ~WinsockManager(){
        WSACleanup();
    }

    static WinsockManager& GetInstance() {
        static WinsockManager instance;
        return instance;
    }

private:
    std::atomic<bool> m_initialised{false};
};
#endif


}