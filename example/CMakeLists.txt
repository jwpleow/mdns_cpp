add_executable(service_discovery
  service_discovery.cpp
)

target_link_libraries(service_discovery
  mdns_cpp::mdns_cpp
)

add_executable(mdns_client
  mdns_client.cpp
)

target_link_libraries(mdns_client
  mdns_cpp::mdns_cpp
)