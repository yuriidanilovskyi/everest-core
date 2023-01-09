// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest
#include "ISO15118_chargerImpl.hpp"
#include "log.hpp"
#include "v2g_ctx.hpp"


namespace module {
namespace charger {

void ISO15118_chargerImpl::init() {
    if (!v2g_ctx) {
        dlog(DLOG_LEVEL_ERROR, "v2g_ctx not created");
        return;
    }

    v2g_ctx->ifname = mod->config.device.data();
    dlog(DLOG_LEVEL_DEBUG, "ifname %s", v2g_ctx->ifname);
    const char *authMode = mod->config.highlevel_authentication_mode.data();
    dlog(DLOG_LEVEL_DEBUG, "authMode %s", authMode);
    if (strstr(authMode, "eim") != NULL) {
        v2g_ctx->ci_evse.payment_option_list[v2g_ctx->ci_evse.payment_option_list_len] =  iso1paymentOptionType_ExternalPayment;
        v2g_ctx->ci_evse.payment_option_list_len++;
    }
    if (strstr(authMode, "pnc") != NULL) {
        v2g_ctx->ci_evse.payment_option_list[v2g_ctx->ci_evse.payment_option_list_len] =  iso1paymentOptionType_Contract;
        v2g_ctx->ci_evse.payment_option_list_len++;
    }
    if (strstr(authMode, "pnc_online") != NULL) {
        v2g_ctx->pncOnlineMode = true;
    }
    else {
        v2g_ctx->pncOnlineMode = false;
    }

    /* Configure hlc_protocols */
    if (mod->config.supported_DIN70121 == true) {
        v2g_ctx->supported_protocols |= (1 << V2G_PROTO_DIN70121);
    }
    if (mod->config.supported_ISO15118_2 == true) {
        v2g_ctx->supported_protocols |= (1 << V2G_PROTO_ISO15118_2013);
    }

    /* Configure tls_security */
    const char *tls_security = mod->config.tls_security.data();
    if (mod->config.tls_security.compare("force") == 0) {
        v2g_ctx->tls_security = TLS_SECURITY_FORCE;
        dlog(DLOG_LEVEL_DEBUG, "tls_security force");
    }
    else if (mod->config.tls_security.compare("allow") == 0) {
        v2g_ctx->tls_security = TLS_SECURITY_ALLOW;
        dlog(DLOG_LEVEL_DEBUG, "tls_security allow");
    }
    else {
        v2g_ctx->tls_security = TLS_SECURITY_PROHIBIT;
        dlog(DLOG_LEVEL_DEBUG, "tls_security prohibit");
    }
}

void ISO15118_chargerImpl::ready() {
}

void ISO15118_chargerImpl::handle_set_EVSEID(std::string& EVSEID, std::string& EVSEID_DIN){
    uint8_t len = EVSEID.length();
    if (len < iso1SessionSetupResType_EVSEID_CHARACTERS_SIZE) {
        memcpy(v2g_ctx->ci_evse.evse_id.bytes, reinterpret_cast<uint8_t*>(EVSEID.data()), len);
        v2g_ctx->ci_evse.evse_id.bytesLen = len;
    }
    else {
        dlog(DLOG_LEVEL_WARNING, "EVSEID_CHARACTERS_SIZE exceeded (received: %u, max: %u)", len, iso1SessionSetupResType_EVSEID_CHARACTERS_SIZE);
    }
};

void ISO15118_chargerImpl::handle_set_PaymentOptions(Array& PaymentOptions){
    v2g_ctx->ci_evse.payment_option_list_len = 0;

    for (auto& element : PaymentOptions) {
        if(element.is_string()) {
            if (std::string("Contract").compare(element.get<std::string>()) == 0) {
                v2g_ctx->ci_evse.payment_option_list[v2g_ctx->ci_evse.payment_option_list_len] =  iso1paymentOptionType_Contract;
                v2g_ctx->ci_evse.payment_option_list_len++;
            }
            else if (std::string("ExternalPayment").compare(element.get<std::string>()) == 0) {
                v2g_ctx->ci_evse.payment_option_list[v2g_ctx->ci_evse.payment_option_list_len] =  iso1paymentOptionType_ExternalPayment;
                v2g_ctx->ci_evse.payment_option_list_len++;
            }
            else if (v2g_ctx->ci_evse.payment_option_list_len == 0) {
                dlog(DLOG_LEVEL_WARNING, "Unable to configure PaymentOptions %s", element.get<std::string>());
            }
        }
    }
}

void ISO15118_chargerImpl::handle_set_SupportedEnergyTransferMode(Array& SupportedEnergyTransferMode){
    uint16_t& energyArrayLen = (v2g_ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen);
    iso1EnergyTransferModeType* energyArray = v2g_ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array;
    energyArrayLen = 0;

    uint8_t arrayLen = std::min(iso1SupportedEnergyTransferModeType_EnergyTransferMode_ARRAY_SIZE, 
                        static_cast<int>(SupportedEnergyTransferMode.size()));
    
    for (auto& element : SupportedEnergyTransferMode) {
        if(element.is_string()) {
            if (std::string("AC_single_phase_core").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_AC_single_phase_core;
            }
            else if (std::string("AC_three_phase_core").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_AC_three_phase_core;
            }
            else if (std::string("DC_core").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_DC_core;
            }
            else if (std::string("DC_extended").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_DC_extended;
            }
            else if (std::string("DC_combo_core").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_DC_combo_core;
            }
            else if (std::string("DC_unique").compare(element.get<std::string>()) == 0) {
                energyArray[(energyArrayLen)++] = iso1EnergyTransferModeType_DC_unique;
            }
            else if (energyArrayLen == 0) {
                dlog(DLOG_LEVEL_WARNING, "Unable to configure SupportedEnergyTransferMode %s", element.get<std::string>());
            }
        }
    }
};

void ISO15118_chargerImpl::handle_set_AC_EVSENominalVoltage(double& EVSENominalVoltage){
    populate_physical_value(&v2g_ctx->ci_evse.evse_nominal_voltage, (long long int) EVSENominalVoltage, iso1unitSymbolType_V);
};

void ISO15118_chargerImpl::handle_set_DC_EVSECurrentRegulationTolerance(double& EVSECurrentRegulationTolerance){
    populate_physical_value(&v2g_ctx->ci_evse.evse_current_regulation_tolerance, (long long int) EVSECurrentRegulationTolerance, iso1unitSymbolType_A);
    v2g_ctx->ci_evse.evse_current_regulation_tolerance_is_used = 1;
};

void ISO15118_chargerImpl::handle_set_DC_EVSEPeakCurrentRipple(double& EVSEPeakCurrentRipple){
    populate_physical_value(&v2g_ctx->ci_evse.evse_peak_current_ripple, (long long int) EVSEPeakCurrentRipple, iso1unitSymbolType_A);
};

void ISO15118_chargerImpl::handle_set_ReceiptRequired(bool& ReceiptRequired){
    v2g_ctx->ci_evse.receipt_required = (int) ReceiptRequired;
};

void ISO15118_chargerImpl::handle_set_FreeService(bool& FreeService){
    v2g_ctx->ci_evse.charge_service.FreeService = (int) FreeService;
};

void ISO15118_chargerImpl::handle_set_EVSEEnergyToBeDelivered(double& EVSEEnergyToBeDelivered){
    populate_physical_value(&v2g_ctx->ci_evse.evse_energy_to_be_delivered, (long long int) EVSEEnergyToBeDelivered, iso1unitSymbolType_Wh);
    v2g_ctx->ci_evse.evse_energy_to_be_delivered_is_used = 1;
};

void ISO15118_chargerImpl::handle_enable_debug_mode(types::iso15118_charger::DebugMode& debug_mode){
    if (debug_mode == types::iso15118_charger::DebugMode::None) {
        v2g_ctx->pncDebugMode = false;
    } else {
        v2g_ctx->pncDebugMode = true;
    }
};

void ISO15118_chargerImpl::handle_set_Auth_Okay_EIM(bool& auth_okay_eim){
    if (auth_okay_eim == true) {
        v2g_ctx->ci_evse.evse_processing[PHASE_AUTH] = (uint8_t) iso1EVSEProcessingType_Finished;
    } else {
        v2g_ctx->ci_evse.evse_processing[PHASE_AUTH] = (uint8_t) iso1EVSEProcessingType_Ongoing;
    }
};

void ISO15118_chargerImpl::handle_set_Auth_Okay_PnC(bool& auth_okay_pnc){
    if (auth_okay_pnc == true) {
        v2g_ctx->ci_evse.evse_processing[PHASE_AUTH] = (uint8_t) iso1EVSEProcessingType_Finished;
    } else {
        v2g_ctx->ci_evse.evse_processing[PHASE_AUTH] = (uint8_t) iso1EVSEProcessingType_Ongoing;
    }
};

void ISO15118_chargerImpl::handle_set_FAILED_ContactorError(bool& ContactorError){
    // TODO your code for cmd set_FAILED_ContactorError goes here
};

void ISO15118_chargerImpl::handle_set_RCD_Error(bool& RCD){
    v2g_ctx->ci_evse.rcd = (int) RCD;
};

void ISO15118_chargerImpl::handle_stop_charging(bool& stop_charging){
    // your code for cmd stop_charging goes here
};

void ISO15118_chargerImpl::handle_set_DC_EVSEPresentVoltageCurrent(
    types::iso15118_charger::DC_EVSEPresentVoltage_Current& EVSEPresentVoltage_Current){
    populate_physical_value_float(&v2g_ctx->ci_evse.evse_present_voltage, EVSEPresentVoltage_Current.EVSEPresentVoltage, 1, iso1unitSymbolType_V);
    populate_physical_value_float(&v2g_ctx->ci_evse.evse_present_current, static_cast<float>(*EVSEPresentVoltage_Current.EVSEPresentCurrent), 1, iso1unitSymbolType_A);
};

void ISO15118_chargerImpl::handle_set_AC_EVSEMaxCurrent(double& EVSEMaxCurrent){
    v2g_ctx->basicConfig.evse_ac_current_limit = (float) EVSEMaxCurrent;
};

void ISO15118_chargerImpl::handle_set_DC_EVSEMaximumLimits(
    types::iso15118_charger::DC_EVSEMaximumLimits& EVSEMaximumLimits){
    populate_physical_value(&v2g_ctx->ci_evse.evse_maximum_current_limit, (long long int) EVSEMaximumLimits.EVSEMaximumCurrentLimit, iso1unitSymbolType_A);
    v2g_ctx->ci_evse.evse_maximum_current_limit_is_used = 1;

    struct iso1PhysicalValueType tmpPowerLimit;
	populate_physical_value(&tmpPowerLimit, (long long int) EVSEMaximumLimits.EVSEMaximumPowerLimit, iso1unitSymbolType_W);
	setMinPhysicalValue(&v2g_ctx->ci_evse.evse_maximum_power_limit, &tmpPowerLimit, &v2g_ctx->ci_evse.evse_maximum_power_limit_is_used);

    populate_physical_value(&v2g_ctx->ci_evse.evse_maximum_voltage_limit, (long long int) EVSEMaximumLimits.EVSEMaximumVoltageLimit, iso1unitSymbolType_V);
    v2g_ctx->ci_evse.evse_maximum_voltage_limit_is_used = 1;
};

void ISO15118_chargerImpl::handle_set_DC_EVSEMinimumLimits(
    types::iso15118_charger::DC_EVSEMinimumLimits& EVSEMinimumLimits){
    populate_physical_value(&v2g_ctx->ci_evse.evse_minimum_current_limit, (long long int) EVSEMinimumLimits.EVSEMinimumCurrentLimit, iso1unitSymbolType_A);

    populate_physical_value(&v2g_ctx->ci_evse.evse_minimum_voltage_limit, (long long int) EVSEMinimumLimits.EVSEMinimumVoltageLimit, iso1unitSymbolType_V);
};

void ISO15118_chargerImpl::handle_set_EVSEIsolationStatus(
    types::iso15118_charger::IsolationStatus& EVSEIsolationStatus){
    v2g_ctx->ci_evse.evse_isolation_status = (uint8_t) EVSEIsolationStatus;
    v2g_ctx->ci_evse.evse_isolation_status_is_used = 1;
};

void ISO15118_chargerImpl::handle_set_EVSE_UtilityInterruptEvent(bool& EVSE_UtilityInterruptEvent){
    // utility interrupt event
    if (EVSE_UtilityInterruptEvent == true)
        memset(v2g_ctx->ci_evse.evse_status_code, (int) iso1DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent, sizeof(v2g_ctx->ci_evse.evse_status_code));
};

void ISO15118_chargerImpl::handle_set_EVSE_Malfunction(bool& EVSE_Malfunction){
    // EVSE Malfunction
   if (EVSE_Malfunction == true)
        memset(v2g_ctx->ci_evse.evse_status_code, (int) iso1DC_EVSEStatusCodeType_EVSE_Malfunction, sizeof(v2g_ctx->ci_evse.evse_status_code));
};

void ISO15118_chargerImpl::handle_set_EVSE_EmergencyShutdown(bool& EVSE_EmergencyShutdown){
    v2g_ctx->intl_emergency_shutdown = EVSE_EmergencyShutdown;
};

void ISO15118_chargerImpl::handle_set_MeterInfo(types::powermeter::Powermeter& powermeter){
    // TODO your code for cmd set_MeterInfo goes here
};

void ISO15118_chargerImpl::handle_contactor_closed(bool& status){
    v2g_ctx->ci_evse.contactor_is_closed = status;
};

void ISO15118_chargerImpl::handle_contactor_open(bool& status){
    v2g_ctx->ci_evse.contactor_is_closed = !status;
};

void ISO15118_chargerImpl::handle_cableCheck_Finished(bool& status){
    if (status == true) {
        v2g_ctx->ci_evse.evse_processing[PHASE_ISOLATION] = (uint8_t) iso1EVSEProcessingType_Finished;
    } else {
        v2g_ctx->ci_evse.evse_processing[PHASE_ISOLATION] = (uint8_t) iso1EVSEProcessingType_Ongoing;
    }
};

} // namespace charger
} // namespace module
