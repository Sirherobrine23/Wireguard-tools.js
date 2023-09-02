#include <napi.h>
#include <wginterface.hh>
#include <net/if.h>

unsigned long maxName() {
  return IFNAMSIZ;
}

void listDevices::Execute() {}
void deleteInterface::Execute() {}
void setConfig::Execute() {}
void getConfig::Execute() {}