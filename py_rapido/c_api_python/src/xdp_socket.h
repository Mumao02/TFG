#ifndef XDP_SOCKET_H
#define XDP_SOCKET_H

int xdp_open(const char *ifname);
int xdp_recv(void *buf, size_t buflen);
void xdp_close();

#endif
