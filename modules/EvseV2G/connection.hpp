// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest

#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include <stddef.h>
#include "v2g_ctx.hpp"

int connection_init(struct v2g_context* ctx);
int connection_start_servers(struct v2g_context *ctx);

#endif /* CONNECTION_H */
