add_executable(mdns_cpp_example
  main.cpp
)

target_link_libraries(mdns_cpp_example
  mdns_cpp::mdns_cpp
)