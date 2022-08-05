#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

int setAdress(const char *ifname, const char *ip_address) {
  int fd;

  // IPv6
  if (!strchr(ip_address, '::')) {
    sockaddr_in* addr;
    /*AF_INET - to define network interface IPv4*/
    /*Creating soket for it.*/
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifreq ifr;
    /*AF_INET - to define IPv4 Address type.*/
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /*defining the sockaddr_in*/
    addr = (sockaddr_in*)&ifr.ifr_addr;

    /*convert ip address in correct format to write*/
    inet_pton(AF_INET, ip_address, &addr->sin_addr);

    /*Setting the Ip Address using ioctl*/
    ioctl(fd, SIOCSIFADDR, &ifr);
  } else {
    sockaddr_in6* addr;
    /*AF_INET6 - to define network interface IPv6*/
    /*Creating soket for it.*/
    fd = socket(AF_INET6, SOCK_DGRAM, 0);

    ifreq ifr;
    /*AF_INET6 - to define IPv6 Address type.*/
    ifr.ifr_addr.sa_family = AF_INET6;
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /*defining the sockaddr_in6*/
    addr = (sockaddr_in6*)&ifr.ifr_addr;

    /*convert ip address in correct format to write*/
    inet_pton(AF_INET6, ip_address, &addr->sin6_addr);

    /*Setting the Ip Address using ioctl*/
    ioctl(fd, SIOCSIFADDR, &ifr);
  }

  // Up the interface
  ifreq ifr;
  strcpy(ifr.ifr_name, ifname);
  ifr.ifr_flags = IFF_UP;
  ioctl(fd, SIOCSIFFLAGS, &ifr);

  /*closing fd*/
  close(fd);
  return 0;
}