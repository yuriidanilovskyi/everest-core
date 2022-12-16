// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest
#ifndef SDP_H
#define SDP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stddef.h>
#include "v2g.h"

int sdp_listen(struct v2g_context *v2g_ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* SDP_H */
