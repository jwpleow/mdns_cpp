cmake_minimum_required(VERSION 3.15)
include_guard(GLOBAL)
project(mdns_cpp)

option(BUILD_EXAMPLE "" ON)

add_subdirectory(external/mdns)
add_subdirectory(external/fmt)

add_library(mdns_cpp
  src/mdns.cpp
  src/types.cpp
)
add_library(mdns_cpp::mdns_cpp ALIAS mdns_cpp)

target_include_directories(mdns_cpp
PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(mdns_cpp
PUBLIC
PRIVATE
  mdns::mdns
  fmt::fmt
)

target_compile_features(mdns_cpp PUBLIC cxx_std_17)

if (BUILD_EXAMPLE)
  add_subdirectory(example)
endif()