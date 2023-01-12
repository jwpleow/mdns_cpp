#pragma once

#include <string_view>

#include <iostream>

namespace mdns_cpp
{

enum class LogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
};

inline void Log(LogLevel level, std::string_view string) {
    // replace with your logger here
    std::cout << string << "\n";
}

}