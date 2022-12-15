// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "auth_token_validatorImpl.hpp"

namespace module {
namespace main {

void auth_token_validatorImpl::init() {
}

void auth_token_validatorImpl::ready() {
}

types::authorization::ValidationResult auth_token_validatorImpl::handle_validate_token(std::string& id_token) {
    std::this_thread::sleep_for(std::chrono::duration<double>(this->config.sleep));
    types::authorization::ValidationResult result;
    result.authorization_status = types::authorization::string_to_authorization_status(this->config.validation_result);
    result.reason.emplace(this->config.validation_reason);
    return result;
};

} // namespace main
} // namespace module
