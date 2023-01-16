// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "auth_token_providerImpl.hpp"

namespace module {
namespace main {

void auth_token_providerImpl::init() {
}

void auth_token_providerImpl::ready() {
        this->mod->r_evse->subscribe_session_event([this](types::evse_manager::SessionEvent session_event) {
        if (session_event.event == types::evse_manager::SessionEventEnum::AuthRequired) {
            types::authorization::ProvidedIdToken token;
            token.id_token = this->config.token;
            token.type = types::authorization::string_to_token_type(this->config.type);
            this->mod->p_main->publish_provided_token(token);
        }
    });
}

} // namespace main
} // namespace module
