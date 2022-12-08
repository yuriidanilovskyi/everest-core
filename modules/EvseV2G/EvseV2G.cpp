// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#include "EvseV2G.hpp"

namespace module {

void EvseV2G::init() {
    invoke_init(*p_charger);
}

void EvseV2G::ready() {
    invoke_ready(*p_charger);
}

} // namespace module
