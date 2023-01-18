add_executable(service_discovery
  service_discovery.cpp
)

target_link_libraries(service_discovery
  mdns_cpp::mdns_cpp
)

add_executable(mdns_service
  mdns_service.cpp
)

target_link_libraries(mdns_service
  mdns_cpp::mdns_cpp
)