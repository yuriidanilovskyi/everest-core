// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#include "board_support_ACImpl.hpp"

namespace module {
namespace board_support {

types::board_support::Event cast_event_type(const ControlPilot::Event& e) {
    switch (e) {
    case ControlPilot::Event::CarPluggedIn:
        return types::board_support::Event::CarPluggedIn;
    case ControlPilot::Event::CarRequestedPower:
        return types::board_support::Event::CarRequestedPower;
    case ControlPilot::Event::PowerOn:
        return types::board_support::Event::PowerOn;
    case ControlPilot::Event::PowerOff:
        return types::board_support::Event::PowerOff;
    case ControlPilot::Event::CarRequestedStopPower:
        return types::board_support::Event::CarRequestedStopPower;
    case ControlPilot::Event::CarUnplugged:
        return types::board_support::Event::CarUnplugged;
    case ControlPilot::Event::Error_E:
        return types::board_support::Event::ErrorE;
    case ControlPilot::Event::Error_DF:
        return types::board_support::Event::ErrorDF;
    case ControlPilot::Event::Error_Relais:
        return types::board_support::Event::ErrorRelais;
    case ControlPilot::Event::Error_RCD:
        return types::board_support::Event::ErrorRCD;
    case ControlPilot::Event::Error_VentilationNotAvailable:
        return types::board_support::Event::ErrorVentilationNotAvailable;
    case ControlPilot::Event::Error_OverCurrent:
        return types::board_support::Event::ErrorOverCurrent;
    case ControlPilot::Event::EnterBCD:
        return types::board_support::Event::EnterBCD;
    case ControlPilot::Event::LeaveBCD:
        return types::board_support::Event::LeaveBCD;
    case ControlPilot::Event::PermanentFault:
        return types::board_support::Event::PermanentFault;
    case ControlPilot::Event::EvseReplugStarted:
        return types::board_support::Event::EvseReplugStarted;
    case ControlPilot::Event::EvseReplugFinished:
        return types::board_support::Event::EvseReplugFinished;
    }

    EVLOG_AND_THROW(Everest::EverestConfigError("Received an unknown interface event from Yeti"));
}

void board_support_ACImpl::init() {
    // initialize gpio and pwm

    control_pilot_hal = std::make_shared<ControlPilot_HAL>();
    power_switch = std::make_shared<PowerSwitch>();
    control_pilot = std::make_shared<ControlPilot>(control_pilot_hal, power_switch);
}

void board_support_ACImpl::ready() {
    charger_thread = std::thread([this]() {
        while (true) {
            // Run low level state machine update
            auto cp_events = control_pilot->runStateMachine();
            // we just proxy the ControlPilot interface to protobuf
            while (!cp_events.empty()) {
                auto cp_event = cp_events.front();
                cp_events.pop();

                // Forward signals to RemoteControl
                auto event = cast_event_type(cp_event);
                auto event_str = types::board_support::event_to_string(event);
                EVLOG_info << "Event: " << event_str;
                publish_event(event);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    telemetry_thread = std::thread([this]() {
        while (true) {
            publish_nr_of_phases_available((control_pilot->getThreePhases() ? 3 : 1));

            types::board_support::Telemetry telemetry;
            telemetry.temperature = 0.;
            telemetry.fan_rpm = 0.;
            telemetry.supply_voltage_12V = control_pilot->getSupply12V();
            telemetry.supply_voltage_minus_12V = control_pilot->getSupplyN12V();
            telemetry.rcd_current = 0;
            telemetry.relais_on = power_switch->isOn();

            publish_telemetry(telemetry);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    });
}

void board_support_ACImpl::handle_setup(bool& three_phases, bool& has_ventilation, std::string& country_code,
                                        bool& rcd_enabled) {
    // FIXME
    control_pilot->setThreePhases(three_phases);
    control_pilot->setHasVentilation(has_ventilation);
    control_pilot->setCountryCode(country_code.c_str());
};

types::board_support::HardwareCapabilities board_support_ACImpl::handle_get_hw_capabilities() {
    types::board_support::HardwareCapabilities caps;
    caps.min_current_A = control_pilot->getMinCurrentA();
    caps.max_current_A = control_pilot->getMaxCurrentA();
    caps.min_phase_count = control_pilot->getMinPhaseCount();
    caps.max_phase_count = control_pilot->getMaxPhaseCount();
    caps.supports_changing_phases_during_charging = false;

    return caps;
};

void board_support_ACImpl::handle_enable(bool& value) {
    control_pilot->enable();
};

void board_support_ACImpl::handle_pwm_on(double& value) {
    control_pilot->pwmOn(value);
};

void board_support_ACImpl::handle_pwm_off() {
    control_pilot->pwmOff();
};

void board_support_ACImpl::handle_pwm_F() {
    control_pilot->pwmF();
};

void board_support_ACImpl::handle_allow_power_on(bool& value) {
    control_pilot->allowPowerOn(value);
};

bool board_support_ACImpl::handle_force_unlock() {
    control_pilot->forceUnlock();
    return true; // FIXME
};

void board_support_ACImpl::handle_switch_three_phases_while_charging(bool& value) {
    control_pilot->switchThreePhasesWhileCharging(value);
};

void board_support_ACImpl::handle_evse_replug(int& value) {
    control_pilot->replug(value);
};

} // namespace board_support
} // namespace module
