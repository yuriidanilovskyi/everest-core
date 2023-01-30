// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest
#ifndef MAIN_ISOLATION_MONITOR_IMPL_HPP
#define MAIN_ISOLATION_MONITOR_IMPL_HPP

//
// AUTO GENERATED - MARKED REGIONS WILL BE KEPT
// template version 3
//

#include <generated/interfaces/isolation_monitor/Implementation.hpp>

#include "../IMDSimulator.hpp"

// ev@75ac1216-19eb-4182-a85c-820f1fc2c091:v1
// insert your custom include headers here
#include <atomic>
#include <pthread.h>
// ev@75ac1216-19eb-4182-a85c-820f1fc2c091:v1

namespace module {
namespace main {

struct Conf {
    double resistance_N_Ohm;
    double resistance_P_Ohm;
    int interval;
};

class isolation_monitorImpl : public isolation_monitorImplBase {
public:
    isolation_monitorImpl() = delete;
    isolation_monitorImpl(Everest::ModuleAdapter* ev, const Everest::PtrContainer<IMDSimulator>& mod, Conf& config) :
        isolation_monitorImplBase(ev, "main"), mod(mod), config(config){};
    ~isolation_monitorImpl();

    // ev@8ea32d28-373f-4c90-ae5e-b4fcc74e2a61:v1
    types::isolation_monitor::IsolationMeasurement isolation_measurement;
    bool stop_isolation_monitoring;
    int config_interval;
    pthread_mutex_t mqtt_lock;
    pthread_cond_t mqtt_cond;
    pthread_condattr_t mqtt_attr;
    friend void* isolation_measurement_cb(isolation_monitorImpl* isolation_Impl);
    // ev@8ea32d28-373f-4c90-ae5e-b4fcc74e2a61:v1

protected:
    // command handler functions (virtual)
    virtual void handle_start() override;
    virtual void handle_stop() override;

    // ev@d2d1847a-7b88-41dd-ad07-92785f06f5c4:v1
    // insert your protected definitions here
    // ev@d2d1847a-7b88-41dd-ad07-92785f06f5c4:v1

private:
    const Everest::PtrContainer<IMDSimulator>& mod;
    const Conf& config;

    virtual void init() override;
    virtual void ready() override;

    // ev@3370e4dd-95f4-47a9-aaec-ea76f34a66c9:v1
    // insert your private definitions here
    pthread_t thread;
    // ev@3370e4dd-95f4-47a9-aaec-ea76f34a66c9:v1
};

// ev@3d7da0ad-02c2-493d-9920-0bbbd56b9876:v1
// insert other definitions here
void* isolation_measurement_cb(isolation_monitorImpl* isolation_Impl);
void set_normalized_timespec(struct timespec *ts, time_t sec, int64_t nsec);
void timespec_add_ms(struct timespec *ts, long long msec);
// ev@3d7da0ad-02c2-493d-9920-0bbbd56b9876:v1

} // namespace main
} // namespace module

#endif // MAIN_ISOLATION_MONITOR_IMPL_HPP
