// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest
#include "EvseV2G.hpp"
#include "log.hpp"

struct v2g_context *v2g_ctx = NULL;

namespace module {

void EvseV2G::init() {
    /* create v2g context */
    v2g_ctx = v2g_ctx_create();
    invoke_init(*p_charger);
}

void EvseV2G::ready() {
    invoke_ready(*p_charger);
}

EvseV2G::~EvseV2G() {
	v2g_ctx_free(v2g_ctx);
}

} // namespace module
