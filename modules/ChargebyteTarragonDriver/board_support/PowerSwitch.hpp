/*
 * PowerSwitch.hpp
 *
 *  Created on: 26.02.2021
 *      Author: cornelius
 *
 * Driver for the two power Relais.
 *
 * switchOnSinglePhase()/switchOnThreePhase() enables power output to the
 * car. Note that power can only be switched on from off state, you cannot
 * switch e.g. from single phase to three phase without switching off in between
 * and start a new charging cycle.
 *
 * The driver monitors the mirror contacts for both relais and sets
 * relaisHealthy to false if the mirror contacts do not work as expected. The
 * same happens if trying to switch on from on state. There is no way to recover
 * from this error except power cycling the whole system for safety reasons.
 *
 * emergencySwitchOff() switches off and sets relaisHealthy to false with
 * no way to recover. Used to switch off from RCD.
 *
 *
 */

#ifndef SRC_EVDRIVERS_POWERSWITCH_H_
#define SRC_EVDRIVERS_POWERSWITCH_H_

#include <boost/filesystem.hpp>
#include <cstdint>
#include <stdio.h>



class PowerSwitch {
public:
    PowerSwitch(bool sense_1_active, bool sense_2_active);
    ~PowerSwitch();
    bool switchOnSinglePhase();
    bool switchOnThreePhase();
    bool switchOff();
    bool isOn();

    bool executeSelfTest();
    void emergencySwitchOff();
    void resetEmergencySwitchOff();

private:
    bool relaisOn;
    bool relaisHealthy;
    bool sense_1_active;
    bool sense_2_active;

    bool isActiveRelay1();
    bool isActiveRelay2();
    void enableRelay1();
    void disableRelay1();
    void enableRelay2();
    void disableRelay2();

    const uint32_t relaisHoldingPercent = 30;

    boost::filesystem::path relay_1_path;
    boost::filesystem::path relay_2_path;
    boost::filesystem::path relay_1_sense_path;
    boost::filesystem::path relay_2_sense_path;

    // time relais takes to switch on/off in ms
    const uint16_t relaisDelay = 100;
};

#endif // SRC_EVDRIVERS_POWERSWITCH_H_
