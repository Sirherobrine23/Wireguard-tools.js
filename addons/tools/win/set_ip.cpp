#include <string>
#include <vector>
#include <iostream>

// Set interface IPv4 address in Windows
std::string SetNetworkAddressIPv4(std::vector<std::string> IPs) {
  for (auto & IP : IPs) {
    std::cout << IP << std::endl;
  }
  return "";
}

// Set interface IPv6 address in Windows
std::string SetNetworkAddressIPv6(std::vector<std::string> IPs) {
  for (auto & IP : IPs) {
    std::cout << IP << std::endl;
  }
  return "";
}