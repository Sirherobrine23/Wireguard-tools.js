#include <netlink/netlink.h>
#include <netlink/route/link.h>

int createInterface(char interfaceName) {
    struct rtnl_link *link;
    struct nl_sock *sk;
    int err = 0;

    link = rtnl_link_alloc();
    if (!link) {
        nl_perror(err, "rtnl_link_alloc");
        goto OUT;
    }
    rtnl_link_set_name(link, interfaceName);
    rtnl_link_set_type(link, "wireguard");

    sk = nl_socket_alloc();
    err = nl_connect(sk, NETLINK_ROUTE);
    if (err < 0) {
        nl_perror(err, "nl_connect");
        goto CLEANUP_LINK;
    }
    err = rtnl_link_add(sk, link, NLM_F_CREATE);
    if (err < 0) {
        nl_perror(err, "");
        goto CLEANUP_SOCKET;
    }

CLEANUP_SOCKET:
    nl_close(sk);
CLEANUP_LINK:
    rtnl_link_put(link);
OUT:
    return err;
}
