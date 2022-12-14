/*
 * ControlPilot_HAL.hpp
 *
 *  Created on: 25.10.2021
 *  Author: cornelius
 *
 * IEC 61851-1 compliant Control Pilot state machine
 *
 * This class provides HAL abstraction for CP and PP signals:
 * 1) ADC readings of PWM signal on CP
 * 2) PWM output on CP
 * 3) CP enable/disable (high impedance)
 * 4) PP reading (not implemented yet)
 * 5) Lock motor control (not implemented yet)
 * 6) supply voltage reading (not possible?)
 *
 */

#ifndef SRC_EVDRIVERS_CONTROLPILOT_HAL_H_
#define SRC_EVDRIVERS_CONTROLPILOT_HAL_H_

#include <boost/filesystem.hpp>
#include <cstdint>

class ControlPilot_HAL {
public:
    ControlPilot_HAL();
    virtual ~ControlPilot_HAL();

    bool readCPSignal();
    float getCPHi();
    float getCPLo();
    float getSupply12V();
    float getSupplyN12V();

    void lockMotorLock();
    void lockMotorUnlock();
    void lockMotorOff();

    void setPWM(float dc);
    void disableCP();
    void enableCP();

    int32_t getMinPhaseCount();
    int32_t getMaxPhaseCount();
    int32_t getMinCurrentA();
    int32_t getMaxCurrentA();

private:
    float cpLo, cpHi;

    float f1(float a);
    float f2(float s);

    int32_t min_phase_count;
    int32_t max_phase_count;
    int32_t min_current_a;
    int32_t max_current_a;

    boost::filesystem::path adc_device_path;
};

#endif // SRC_EVDRIVERS_CONTROLPILOT_HAL_H_
