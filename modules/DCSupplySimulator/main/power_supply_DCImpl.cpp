// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <time.h>

#include "power_supply_DCImpl.hpp"

namespace module {
namespace main {

void power_supply_DCImpl::init() {
    connector_voltage = 0.0;
    pthread_mutex_init(&mqtt_lock, NULL);
    pthread_condattr_init(&mqtt_attr);
    pthread_condattr_setclock(&mqtt_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&mqtt_cond, &mqtt_attr);
}

void power_supply_DCImpl::ready() {
    struct timespec ts_abs_timeout;
    int rv = 0;
    types::power_supply_DC::VoltageCurrent voltage_current;

    // set interval for 500 milliseconds to publish
    clock_gettime(CLOCK_MONOTONIC, &ts_abs_timeout);
    timespec_add_ms(&ts_abs_timeout, 500);

    while (1){
        pthread_mutex_lock(&mqtt_lock);
        rv = pthread_cond_timedwait(&mqtt_cond, &mqtt_lock, &ts_abs_timeout);

        if (rv == ETIMEDOUT) {
            // when timeout occurs, publish and reset the timer to publish again after 500 milliseconds
            rv = 0;
            voltage_current.voltage_V = connector_voltage;
            voltage_current.current_A = 0.1;
            mod->p_main->publish_voltage_current(voltage_current);
            clock_gettime(CLOCK_MONOTONIC, &ts_abs_timeout);
            timespec_add_ms(&ts_abs_timeout, 500);
        }
        pthread_mutex_unlock(&mqtt_lock);
    }
}

types::power_supply_DC::Capabilities power_supply_DCImpl::handle_getCapabilities() {
    types::power_supply_DC::Capabilities Capabilities = {
            .bidirectional = config.bidirectional,
            .current_regulation_tolerance_A = 2.0,
            .peak_current_ripple_A = 2.0,
            .max_export_voltage_V =  static_cast<float>(config.max_voltage),
            .min_export_voltage_V = static_cast<float>(config.min_voltage),
            .max_export_current_A = static_cast<float>(config.max_current),
            .min_export_current_A = static_cast<float>(config.min_current),
            .max_export_power_W = static_cast<float>(config.max_power),
            .max_import_voltage_V = config.max_voltage,
            .min_import_voltage_V = config.min_voltage,
            .max_import_current_A = config.max_current,
            .min_import_current_A = config.min_current,
            .max_import_power_W = config.max_power,
    };
    return Capabilities;
};

void power_supply_DCImpl::handle_setMode(types::power_supply_DC::Mode& value){
    mode = value;

    if ((value == types::power_supply_DC::Mode::Off) || (value == types::power_supply_DC::Mode::Fault)) {
        connector_voltage = 0.0;
    }
    else if (value == types::power_supply_DC::Mode::Export) {
        connector_voltage = settings_connector_export_voltage;
    }
    else if (value == types::power_supply_DC::Mode::Import) {
        connector_voltage = settings_connector_import_voltage;
    }

    mod->p_main->publish_mode(value);
};

void power_supply_DCImpl::handle_setExportVoltageCurrent(double& voltage, double& current){
    temp_voltage = voltage;
    temp_current = current;

    temp_voltage = temp_voltage < config.min_voltage ? config.min_voltage : temp_voltage > config.max_voltage ? config.max_voltage : temp_voltage;
    temp_current = temp_current < config.min_current ? config.min_current : temp_current > config.max_current ? config.max_current : temp_current;

    settings_connector_export_voltage = temp_voltage;
    settings_connector_max_export_current = temp_current;

    if (mode == types::power_supply_DC::Mode::Export) {
        connector_voltage = settings_connector_export_voltage;
    }
};

void power_supply_DCImpl::handle_setImportVoltageCurrent(double& voltage, double& current){
    temp_voltage = voltage;
    temp_current = current;

    temp_voltage = temp_voltage < config.min_voltage ? config.min_voltage : temp_voltage > config.max_voltage ? config.max_voltage : temp_voltage;
    temp_current = temp_current < config.min_current ? config.min_current : temp_current > config.max_current ? config.max_current : temp_current;

    settings_connector_import_voltage = temp_voltage;
    settings_connector_max_import_current = temp_current;

    if (mode == types::power_supply_DC::Mode::Import) {
        connector_voltage = settings_connector_import_voltage;
    }
};

// other definitions
#define NSEC_PER_SEC 1000000000L
void set_normalized_timespec(struct timespec *ts, time_t sec, int64_t nsec)
{
    while (nsec >= NSEC_PER_SEC) {
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while (nsec < 0) {
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}

void timespec_add_ms(struct timespec *ts, long long msec)
{
    long long sec = msec / 1000;

    set_normalized_timespec(ts, ts->tv_sec + sec, ts->tv_nsec + (msec - sec * 1000) * 1000 * 1000);
}

} // namespace main
} // namespace module
