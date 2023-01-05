// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "connection.h"
#include "tools.h"
#include "log.hpp"

#define DEFAULT_SOCKET_BACKLOG  3
#define DEFAULT_TCP_PORT        61341
#define DEFAULT_TLS_PORT        64109

static int connection_create_socket(struct sockaddr_in6 *sockaddr) {
	socklen_t addrlen = sizeof(*sockaddr);
	int s, enable = 1;
	static bool error_once = false;

	/* create socket */
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == -1) {
		if (!error_once) {
			dlog(DLOG_LEVEL_ERROR, "socket() failed: %s", strerror(errno));
			error_once = true;
		}
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == -1) {
		if (!error_once) {
			dlog(DLOG_LEVEL_ERROR, "setsockopt(SO_REUSEPORT) failed: %s", strerror(errno));
			error_once = true;
		}
		close(s);
		return -1;
	}

	/* bind it to interface */
	if (bind(s, (struct sockaddr *)sockaddr, addrlen) == -1) {
		if (!error_once) {
			dlog(DLOG_LEVEL_WARNING, "bind() failed: %s", strerror(errno));
			error_once = true;
		}
		close(s);
		return -1;
	}

	/* listen on this socket */
	if (listen(s, DEFAULT_SOCKET_BACKLOG) == -1) {
		if (!error_once) {
			dlog(DLOG_LEVEL_ERROR, "listen() failed: %s", strerror(errno));
			error_once = true;
		}
		close(s);
		return -1;
	}

	/* retrieve the actual port number we are listening on */
	if (getsockname(s, (struct sockaddr *)sockaddr, &addrlen) == -1) {
		if (!error_once) {
			dlog(DLOG_LEVEL_ERROR, "getsockname() failed: %s", strerror(errno));
			error_once = true;
		}
		close(s);
		return -1;
	}

	return s;
}

int connection_init(struct v2g_context* v2g_ctx) {
	if (v2g_ctx->tls_security != TLS_SECURITY_FORCE) {
		v2g_ctx->local_tcp_addr = calloc(1, sizeof(*v2g_ctx->local_tcp_addr));
		if (v2g_ctx->local_tcp_addr == NULL) {
			dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for TCP address");
			return -1;
		}
	}

	if (v2g_ctx->tls_security != TLS_SECURITY_PROHIBIT && v2g_ctx->evse_charging_type != CHARGING_TYPE_FAKE_HLC) {
		v2g_ctx->local_tls_addr = calloc(1, sizeof(*v2g_ctx->local_tls_addr));
		if (!v2g_ctx->local_tls_addr) {
			dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for TLS address");
			return -1;
		}
	}

	while (1) {
		if (v2g_ctx->local_tcp_addr) {
			get_interface_ipv6_address(v2g_ctx->ifname, ADDR6_TYPE_LINKLOCAL, v2g_ctx->local_tcp_addr);
			if (v2g_ctx->local_tls_addr) {
				// Handle allowing TCP with TLS (TLS_SECURITY_ALLOW)
				memcpy(v2g_ctx->local_tls_addr, v2g_ctx->local_tcp_addr, sizeof(*v2g_ctx->local_tls_addr));
			}
		} else {
			// Handle forcing TLS security (TLS_SECURITY_FORCE)
			get_interface_ipv6_address(v2g_ctx->ifname, ADDR6_TYPE_LINKLOCAL, v2g_ctx->local_tls_addr);
		}

		if (v2g_ctx->local_tcp_addr) {
			char buffer[INET6_ADDRSTRLEN];

			/*
			 * When we bind with port = 0, the kernel assigns a dynamic port from the range configured
			 * in /proc/sys/net/ipv4/ip_local_port_range. This is on a recent Ubuntu Linux e.g.
			 * $ cat /proc/sys/net/ipv4/ip_local_port_range
			 * 32768   60999
			 * However, in ISO15118 spec the IANA range with 49152 to 65535 is referenced. So we have the
			 * problem that the kernel (without further configuration - and we want to avoid this) could
			 * hand out a port which is not "range compatible".
			 * To fulfill the ISO15118 standard, we simply try to bind to static port numbers.
			 */
			v2g_ctx->local_tcp_addr->sin6_port = htons(DEFAULT_TCP_PORT);
			v2g_ctx->tcp_socket = connection_create_socket(v2g_ctx->local_tcp_addr);
			if (v2g_ctx->tcp_socket < 0) {
				/* retry until interface is ready */
				sleep(1);
				continue;
			}
			if (inet_ntop(AF_INET6, &v2g_ctx->local_tcp_addr->sin6_addr, buffer, sizeof(buffer)) != NULL) {
				dlog(DLOG_LEVEL_INFO, "TCP server on %s is listening on port [%s%%%" PRIu32 "]:%" PRIu16 ,
						v2g_ctx->ifname, buffer, v2g_ctx->local_tcp_addr->sin6_scope_id, ntohs(v2g_ctx->local_tcp_addr->sin6_port));
			} else {
				dlog(DLOG_LEVEL_ERROR, "TCP server on %s is listening, but inet_ntop failed: %s", v2g_ctx->ifname, strerror(errno));
				return -1;
			}
		}

		if (v2g_ctx->local_tls_addr) {
			char buffer[INET6_ADDRSTRLEN];

			/* see comment above for reason */
			v2g_ctx->local_tls_addr->sin6_port = htons(DEFAULT_TLS_PORT);

			v2g_ctx->tls_socket.fd = connection_create_socket(v2g_ctx->local_tls_addr);
			if (v2g_ctx->tls_socket.fd < 0) {
				if (v2g_ctx->tcp_socket != -1) {
					/* free the TCP socket */
					close(v2g_ctx->tcp_socket);
				}
				/* retry until interface is ready */
				sleep(1);
				continue;
			}

			if (inet_ntop(AF_INET6, &v2g_ctx->local_tls_addr->sin6_addr, buffer, sizeof(buffer)) != NULL) {
				dlog(DLOG_LEVEL_INFO, "TLS server on %s is listening on port [%s%%%" PRIu32 "]:%" PRIu16 ,
						v2g_ctx->ifname, buffer, v2g_ctx->local_tls_addr->sin6_scope_id, ntohs(v2g_ctx->local_tls_addr->sin6_port));
			} else {
				dlog(DLOG_LEVEL_INFO, "TLS server on %s is listening, but inet_ntop failed: %s", v2g_ctx->ifname, strerror(errno));
				return -1;
			}
		}
		/* Sockets should be ready, leave the loop */
		break;
	}
	return 0;
}
