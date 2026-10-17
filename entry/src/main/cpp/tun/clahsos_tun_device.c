/* HarmonyOS supplies an already configured TUN fd containing raw IP packets. */
#include <errno.h>
#include <unistd.h>
#include <hev-task.h>
#include <hev-task-io.h>
#include "hev-tunnel.h"

int hev_tunnel_open(const char *name, int multi_queue, const char *guid) { errno = ENOTSUP; return -1; }
void hev_tunnel_close(int fd) { close(fd); }
void hev_tunnel_set_offload(int fd, int offload) { }
int hev_tunnel_get_offload(void) { return 0; }
int hev_tunnel_set_mtu(int mtu) { return 0; }
int hev_tunnel_set_state(int state) { return 0; }
int hev_tunnel_set_ipv4(const char *addr, unsigned int prefix) { return 0; }
int hev_tunnel_set_ipv6(const char *addr, unsigned int prefix) { return 0; }
const char *hev_tunnel_get_name(void) { return "ClashOS"; }
const char *hev_tunnel_get_index(void) { return "0"; }
int hev_tunnel_add_task(int fd, HevTask *task) { return hev_task_add_fd(task, fd, POLLIN); }
void hev_tunnel_del_task(int fd, HevTask *task) { hev_task_del_fd(task, fd); }
