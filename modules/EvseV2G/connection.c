// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest

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
#include "v2g_server.h"

#define DEFAULT_SOCKET_BACKLOG  3
#define DEFAULT_TCP_PORT        61341
#define DEFAULT_TLS_PORT        64109
#define ERROR_SESSION_ALREADY_STARTED  2

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

static void connection_teardown(struct v2g_connection *conn) {
	/* init charging state */
	v2g_ctx_init_charging_state(conn->ctx, true);

	/* open contactor */
	// TODO: Publish DC/AC target contactor state

	/* stop timer */
	stop_timer(&conn->ctx->com_setup_timeout, NULL, conn->ctx);

	/* print dlink status */
	switch (conn->dlink_action) {
		case MQTT_DLINK_ACTION_ERROR:
			dlog( DLOG_LEVEL_TRACE, "d_link/error");
			break;
		case MQTT_DLINK_ACTION_TERMINATE:
			dlog( DLOG_LEVEL_TRACE, "d_link/terminate");
			break;
		case MQTT_DLINK_ACTION_PAUSE:
			dlog( DLOG_LEVEL_TRACE, "d_link/pause");
			break;
	}
}

/**
 * This is the 'main' function of a thread, which handles a TCP connection.
 */
static void *connection_handle_tcp(void *data) {
	struct v2g_connection *conn = (struct v2g_connection *)data;
	int rv = 0;

	dlog(DLOG_LEVEL_INFO, "started new TCP connection thread");

	/* check if the v2g-session is already running in another thread, if not, handle v2g-connection */
	if (conn->ctx->state == 0) {
		int rv2 = v2g_handle_connection(conn);

		if (rv2 != 0) {
			dlog(DLOG_LEVEL_INFO, "v2g_handle_connection exited with %d", rv2);
		}
	}
	else {
		rv = ERROR_SESSION_ALREADY_STARTED;
		dlog(DLOG_LEVEL_WARNING, "%s", "Closing tcp-connection. v2g-session is already running");
	}

	/* tear down connection gracefully */
	dlog(DLOG_LEVEL_INFO, "closing TCP connection");

	if (shutdown(conn->conn.socket_fd, SHUT_RDWR) == -1) {
		dlog(DLOG_LEVEL_ERROR, "shutdown() failed: %s", strerror(errno));
	}
	if (close(conn->conn.socket_fd) == -1) {
		dlog(DLOG_LEVEL_ERROR, "close() failed: %s", strerror(errno));
	}
	dlog(DLOG_LEVEL_INFO, "TCP connection closed gracefully");

	if (rv != ERROR_SESSION_ALREADY_STARTED) {
		/* cleanup and notify lower layers */
		connection_teardown(conn);
	}

	free(conn);

	return NULL;
}

/**
 * This is the 'main' function of a thread, which handles a TLS connection.
 */
static void *connection_handle_tls(void *data) {
	// TODO: handle tls connection
}

static void *connection_server(void *data) {
	struct v2g_context *ctx = (struct v2g_context *)data;
	struct v2g_connection *conn = NULL;
	pthread_attr_t attr;

	/* create the thread in detached state so we don't need to join every single one */
	if (pthread_attr_init(&attr) != 0) {
		dlog(DLOG_LEVEL_ERROR, "pthread_attr_init failed: %s", strerror(errno));
		goto thread_exit;
	}
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		dlog(DLOG_LEVEL_ERROR, "pthread_attr_setdetachstate failed: %s", strerror(errno));
		goto thread_exit;
	}

	while(1) {
		char client_addr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 addr;
		socklen_t addrlen = sizeof(addr);

		/* cleanup old one and create new connection context */
		free(conn);
		conn = calloc(1, sizeof(*conn));
		if (!conn) {
			dlog(DLOG_LEVEL_ERROR, "calloc failed: %s", strerror(errno));
			break;
		}

		/* setup common stuff */
		conn->ctx = ctx;

		/* if this thread is the TLS thread, then connections are TLS secured;
		 * return code is non-zero if equal so align it
		 */
		conn->is_tls_connection = !!pthread_equal(pthread_self(), ctx->tls_thread);

		/* wait for an incoming connection */
		if (conn->is_tls_connection) {
			conn->conn.ssl.ssl_config = &ctx->ssl_config;

			/* at the moment, this is simply resetting the fd to -1; kept for upwards compatibility */
			mbedtls_net_init(&conn->conn.ssl.tls_client_fd);

			conn->conn.ssl.tls_client_fd.fd = accept(ctx->tls_socket.fd, (struct sockaddr *)&addr, &addrlen);
			if (conn->conn.ssl.tls_client_fd.fd == -1) {
				dlog(DLOG_LEVEL_ERROR, "accept(tls) failed: %s", strerror(errno));
				continue;
			}
		} else {
			conn->conn.socket_fd = accept(ctx->tcp_socket, (struct sockaddr *)&addr, &addrlen);
			if (conn->conn.socket_fd == -1) {
				dlog(DLOG_LEVEL_ERROR, "accept(tcp) failed: %s", strerror(errno));
				continue;
			}
		}

		if (inet_ntop(AF_INET6, &addr, client_addr, sizeof(client_addr)) != NULL) {
			dlog(DLOG_LEVEL_INFO, "incoming connection on %s from [%s]:%" PRIu16, ctx->ifname, client_addr, ntohs(addr.sin6_port));
		} else {
			dlog(DLOG_LEVEL_ERROR, "incoming connection on %s, but inet_ntop failed: %s", ctx->ifname, strerror(errno));
		}

		if (pthread_create(&conn->thread_id, &attr,
						   conn->is_tls_connection ? connection_handle_tls : connection_handle_tcp, conn) != 0) {
			dlog(DLOG_LEVEL_ERROR, "pthread_create() failed: %s", strerror(errno));
			continue;
		}

		/* is up to the thread to cleanup conn */
		conn = NULL;
	}

thread_exit:
	if (pthread_attr_destroy(&attr) != 0) {
		dlog(DLOG_LEVEL_ERROR, "pthread_attr_destroy failed: %s", strerror(errno));
	}

	/* clean up if dangling */
	free(conn);

	return NULL;
}

int connection_start_servers(struct v2g_context *ctx) {
	int rv, tcp_started = 0;

	if (ctx->tcp_socket != -1) {
		rv = pthread_create(&ctx->tcp_thread, NULL, connection_server, ctx);
		if (rv != 0) {
			dlog(DLOG_LEVEL_ERROR, "pthread_create(tcp) failed: %s", strerror(errno));
			return -1;
		}
		tcp_started = 1;
	}

	if (ctx->tls_socket.fd != -1) {
		rv = pthread_create(&ctx->tls_thread, NULL, connection_server, ctx);
		if (rv != 0) {
			if (tcp_started) {
				pthread_cancel(ctx->tcp_thread);
				pthread_join(ctx->tcp_thread, NULL);
			}
			dlog(DLOG_LEVEL_ERROR, "pthread_create(tls) failed: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}
