#pragma once

int open_tun(char *name, int nameLength);

int mtu(char const* name, int nameLength);
int set_mtu(char const* name, int nameLength, int mtu);