#include <napi.h>
#include <wginterface.hh>
#include <net/if.h>

unsigned long maxName() {
  return IFNAMSIZ;
}

std::string versionDrive() {
  return "Userspace";
}

void listDevices::Execute() {}
void deleteInterface::Execute() {}
void setConfig::Execute() {}
void getConfig::Execute() {}