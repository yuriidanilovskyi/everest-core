// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest
#include "EvseV2G.hpp"
#include "log.hpp"
#include "sdp.h"

struct v2g_context *v2g_ctx = NULL;

namespace module {

void EvseV2G::init() {
    int rv = 0;
    /* create v2g context */
    v2g_ctx = v2g_ctx_create();
    invoke_init(*p_charger);

    dlog(DLOG_LEVEL_INFO, "starting SDP responder");
    rv = sdp_listen(v2g_ctx);

    if (rv == -1) {
        dlog(DLOG_LEVEL_ERROR, "Failed to start SDP responder");
        goto err_out;
    }

 err_out:
    v2g_ctx_free(v2g_ctx);
}

void EvseV2G::ready() {
    invoke_ready(*p_charger);
}

EvseV2G::~EvseV2G() {
	v2g_ctx_free(v2g_ctx);
}

} // namespace module
