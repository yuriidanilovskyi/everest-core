// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#include "ChargebyteTarragonDriver.hpp"

namespace module {

void ChargebyteTarragonDriver::init() {
    invoke_init(*p_board_support);
}

void ChargebyteTarragonDriver::ready() {
    invoke_ready(*p_board_support);
}

} // namespace module
