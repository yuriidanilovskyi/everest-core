// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVeres
#include "isolation_monitorImpl.hpp"
namespace module {
namespace main {

void isolation_monitorImpl::init() {
    pthread_mutex_init(&mqtt_lock, NULL);
    pthread_condattr_init(&mqtt_attr);
    pthread_condattr_setclock(&mqtt_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&mqtt_cond, &mqtt_attr);

    isolation_measurement.resistance_N_Ohm = config.resistance_N_Ohm;
    isolation_measurement.resistance_P_Ohm = config.resistance_P_Ohm;
    config_interval = config.interval;
}

void isolation_monitorImpl::ready() {
}

isolation_monitorImpl::~isolation_monitorImpl() {
    pthread_join(thread, NULL);
}

void isolation_monitorImpl::handle_start() {
    int res = pthread_create(&thread, NULL, (void* (*)(void*)) &isolation_measurement_cb, this);
    
    if (res) {
        EVLOG_error << "pthread_create error: " << res;
    }
};

void* isolation_measurement_cb(isolation_monitorImpl* isolation_Impl) {
    struct timespec ts_abs_timeout;
    isolation_Impl->stop_isolation_monitoring = false;
    
    EVLOG_error << "Started simulated isolation monitoring with " << isolation_Impl->config_interval << "ms interval";

    // set interval
    clock_gettime(CLOCK_MONOTONIC, &ts_abs_timeout);
    timespec_add_ms(&ts_abs_timeout, isolation_Impl->config_interval);

    while (!isolation_Impl->stop_isolation_monitoring) {
        pthread_mutex_lock(&isolation_Impl->mqtt_lock);

        int rv = pthread_cond_timedwait(&isolation_Impl->mqtt_cond, &isolation_Impl->mqtt_lock, &ts_abs_timeout);

        if (rv == ETIMEDOUT) {
            // when timeout occurs, publish and reset the timer to publish again
            rv = 0;
            isolation_Impl->mod->p_main->publish_IsolationMeasurement(isolation_Impl->isolation_measurement);
            clock_gettime(CLOCK_MONOTONIC, &ts_abs_timeout);
            timespec_add_ms(&ts_abs_timeout, isolation_Impl->config_interval);
            EVLOG_error << "Simulated isolation test finished";
        }
        pthread_mutex_unlock(&isolation_Impl->mqtt_lock);
    }
    EVLOG_error << "Stopped simulated isolation monitoring.";

    return NULL;
}

void isolation_monitorImpl::handle_stop() {
    EVLOG_error << "handle_stop ";
    pthread_mutex_lock(&mqtt_lock);
    stop_isolation_monitoring = true;
    pthread_cond_signal(&mqtt_cond);
    pthread_mutex_unlock(&mqtt_lock);

    pthread_join(thread, NULL);
};

// other definitions
#define NSEC_PER_SEC 1000000000L
void set_normalized_timespec(struct timespec *ts, time_t sec, int64_t nsec) {
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

void timespec_add_ms(struct timespec *ts, long long msec) {
    long long sec = msec / 1000;

    set_normalized_timespec(ts, ts->tv_sec + sec, ts->tv_nsec + (msec - sec * 1000) * 1000 * 1000);
}

} // namespace main
} // namespace module