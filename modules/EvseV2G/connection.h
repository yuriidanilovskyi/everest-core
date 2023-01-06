// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest

#ifndef CONNECTION_H
#define CONNECTION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <netinet/in.h>
#include <stddef.h>
#include "v2g_ctx.h"

int connection_init(struct v2g_context* ctx);
int connection_start_servers(struct v2g_context *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* CONNECTION_H */
