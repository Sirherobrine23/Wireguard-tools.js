#include <unistd.h>
#include <string.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>
#include <netlink/route/rtnl.h>

// https://stackoverflow.com/questions/22244614/adding-route-with-libnl-3-route-invalid-input-data-or-parameter
const char *SucessRouteAdd = "Route added";

int nameToIndex(const char *ifname) {
  rtnl_link *link = NULL;
  nl_sock *sk = NULL;
  nl_cache *link_cache = NULL;
  int err = 0;
  int ifindex = 0;
  sk = nl_socket_alloc();
  if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
    nl_perror(err, "nl_connect");
    return err;
  }
  if ((err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) < 0) {
    nl_perror(err, "rtnl_link_alloc_cache");
    return err;
  }
  if((link = rtnl_link_get_by_name(link_cache, ifname)) == NULL) {
    return -1;
  }
  if((ifindex = rtnl_link_get_ifindex(link)) == 0) {
    fprintf(stderr,"index of %s not set\n", ifname);
    return -1;
  }
  return ifindex;
}

const char *setRoute(const char *ifname, const char *gateway) {
  int ret = 0;
  nl_addr* gatewAddr;
  nl_sock *sock = nl_socket_alloc();
  if (!sock) return "Failed to allocate netlink socket";
  ret = nl_connect(sock, NETLINK_ROUTE);
  if (ret != 0) {
    nl_socket_free(sock);
    return "Failed to connect to netlink socket";
  }

  rtnl_route *rulesRoute = rtnl_route_alloc();
  // Set parameters.
  if (strchr(gateway, ':')) rtnl_route_set_family(rulesRoute, AF_INET6);
  else rtnl_route_set_family(rulesRoute, AF_INET);
  rtnl_route_set_scope(rulesRoute, RT_SCOPE_UNIVERSE);
  rtnl_route_set_scope(rulesRoute, RT_SCOPE_LINK);
  // "proto static" to "scope link"

  nl_addr *dstAddr;
  if (strchr(gateway, ':')) dstAddr = nl_addr_build(AF_INET6, gateway, strlen(gateway));
  else dstAddr = nl_addr_build(AF_INET, gateway, strlen(gateway));

  if (strchr(gateway, ':')) nl_addr_parse(gateway, AF_INET6, &dstAddr);
  else nl_addr_parse(gateway, AF_INET, &dstAddr);

  ret = rtnl_route_set_dst(rulesRoute, dstAddr);
  if (ret != 0) return nl_geterror(ret);

  // Get Interface index
  int ifindex = nameToIndex(ifname);
  if (ifindex == -1) return "Failed to get interface index";

  // Set the next hop.
  if (strchr(gateway, ':')) nl_addr_parse(gateway, AF_INET6, &dstAddr);
  else nl_addr_parse(gateway, AF_INET, &dstAddr);

  // set the gateway address
  rtnl_nexthop *route_nexthop = rtnl_route_nh_alloc();
  rtnl_route_nh_set_ifindex(route_nexthop, ifindex);
  rtnl_route_nh_set_gateway(route_nexthop, gatewAddr);

  rtnl_route_add_nexthop(rulesRoute, route_nexthop);
  ret = rtnl_route_add(sock, rulesRoute, 0);
  if (ret != 0) return nl_geterror(ret);
  nl_socket_free(sock);
  rtnl_route_nh_free(route_nexthop);
  return SucessRouteAdd;
}