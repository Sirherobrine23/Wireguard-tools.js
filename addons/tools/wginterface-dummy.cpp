#include <napi.h>
#include <wginterface.hh>

unsigned long maxName() {
  return 16;
}

std::string versionDrive() {
  return "Userspace";
}

void listDevices::Execute() {}
void deleteInterface::Execute() {}
void setConfig::Execute() {}
void getConfig::Execute() {}