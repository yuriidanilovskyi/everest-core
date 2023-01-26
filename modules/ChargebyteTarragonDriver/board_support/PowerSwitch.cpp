/*
 * PowerSwitch.cpp
 *
 *  Created on: 26.02.2021
 *      Author: cornelius
 */

#include "PowerSwitch.hpp"
#include "utils.hpp"
#include <everest/logging.hpp>

#include <chrono>
#include <thread>

PowerSwitch::PowerSwitch(bool sense_1_active, bool sense_1_simulate, bool sense_2_active) : sense_1_active(sense_1_active), sense_1_simulate(sense_1_simulate), sense_2_active(sense_2_active) {
    // get max phase count and current
    relay_1_path = boost::filesystem::path("/sys/class/gpio/gpio76/value");
    Everest::Utils::wait_until_exists_exception(relay_1_path, std::chrono::milliseconds(200));
    relay_2_path = boost::filesystem::path("/sys/class/gpio/gpio77/value");
    Everest::Utils::wait_until_exists_exception(relay_2_path, std::chrono::milliseconds(200));

    // configure relay gpios as "out"
    Everest::Utils::sysfs_write_string(boost::filesystem::path("/sys/class/gpio/gpio76/direction"), "out");
    Everest::Utils::sysfs_write_string(boost::filesystem::path("/sys/class/gpio/gpio77/direction"), "out");

    relay_1_sense_path = boost::filesystem::path("/sys/class/gpio/gpio131/value");
    Everest::Utils::wait_until_exists_exception(relay_1_sense_path, std::chrono::milliseconds(200));

    relay_2_sense_path = boost::filesystem::path("/sys/class/gpio/gpio130/value");
    Everest::Utils::wait_until_exists_exception(relay_1_sense_path, std::chrono::milliseconds(200));

    // Initialize to known state (off)
    switchOff();

    EVLOG_info << "relays initialized";
    if (relaisHealthy) {
        EVLOG_info << "relays healthy";
    } else {
        EVLOG_warning << "relays not healthy";
    }
}

PowerSwitch::~PowerSwitch() {
    switchOff();
}

bool PowerSwitch::isOn() {
    return relaisOn;
}

bool PowerSwitch::isActiveRelay1() {
    auto relay_1_sense = Everest::Utils::sysfs_read_string(relay_1_sense_path);

    if (this->sense_1_simulate) {
        EVLOG_info << "relaisOn:" << relaisOn;
        return relaisOn;
    }
    else if (this->sense_1_active && relay_1_sense == "1") {
        return true;
    } else if (!this->sense_1_active && relay_1_sense == "0") {
        return true;
    }
    return false;
}

bool PowerSwitch::isActiveRelay2() {
    auto relay_2_sense = Everest::Utils::sysfs_read_string(relay_2_sense_path);

    if (this->sense_2_active && relay_2_sense == "1") {
        return true;
    } else if (!this->sense_2_active && relay_2_sense == "0") {
        return true;
    }

    return false;
}

void PowerSwitch::enableRelay1() {
    Everest::Utils::sysfs_write_string(relay_1_path, "1");
}

void PowerSwitch::disableRelay1() {
    Everest::Utils::sysfs_write_string(relay_1_path, "0");
}

void PowerSwitch::enableRelay2() {
    Everest::Utils::sysfs_write_string(relay_2_path, "1");
}

void PowerSwitch::disableRelay2() {
    Everest::Utils::sysfs_write_string(relay_2_path, "0");
}

bool PowerSwitch::switchOnSinglePhase() {
    // FIXME: there might be no hardware support for this
    if (relaisHealthy) {
        enableRelay1();
        std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));
        relaisOn = true;
        // TODO: no hardware support?
        // setPWML1(relaisHoldingPercent);
        // setPWML2L3(0);

        // EVLOG_info << "switchOnSinglePhase";
        if (isActiveRelay1())
            relaisHealthy = true;
        else
            relaisHealthy = false;
    }
    return relaisHealthy;
}

bool PowerSwitch::switchOnThreePhase() {
    if (relaisHealthy) {
        enableRelay1();
        std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));
        relaisOn = true;
        // TODO: no hardware support?

        // setPWML1(relaisHoldingPercent);
        // setPWML2L3(relaisHoldingPercent);

        // EVLOG_info << "switchOnThreePhase";
        if (isActiveRelay1())
            relaisHealthy = true;
        else
            relaisHealthy = false;
    }
    return relaisHealthy;
}

bool PowerSwitch::switchOff() {
    disableRelay1();
    disableRelay2();
    std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));

    relaisOn = false;
    if (!isActiveRelay1() && !isActiveRelay2())
        relaisHealthy = true;
    else
        relaisHealthy = false;
    return relaisHealthy;
}

bool PowerSwitch::executeSelfTest() {
    bool success = true;
    // printf("   Relais self test...\n");
    // if (switchOnSinglePhase()) {
    //     printf("OK PowerSwitch: SinglePhase on\n");
    // } else {
    //     printf("FAIL PowerSwitch: SinglePhase on\n");
    //     success = false;
    // }
    // osDelay(100);

    // if (switchOff()) {
    //     printf("OK PowerSwitch: SinglePhase off\n");
    // } else {
    //     printf("FAIL PowerSwitch: SinglePhase off\n");
    //     success = false;
    // }
    // osDelay(100);

    // if (switchOnThreePhase()) {
    //     printf("OK PowerSwitch: ThreePhase on\n");
    // } else {
    //     printf("FAIL PowerSwitch: ThreePhase on\n");
    //     success = false;
    // }
    // osDelay(100);

    // if (switchOff()) {
    //     printf("OK PowerSwitch: ThreePhase off\n");
    // } else {
    //     printf("FAIL PowerSwitch: ThreePhase off\n");
    //     success = false;
    // }
    return success;
}

void PowerSwitch::emergencySwitchOff() {
    /* relaisHealthy = false;
     setPWML1(0);
     setPWML2L3(0);
     relaisOn = false;
     printf("+++++++++++++++++++++++ EMERGENCY SWITCHOFF ++++++++++++++++++++++ "
            "\n");
            */
}

void PowerSwitch::resetEmergencySwitchOff() {
    // NOTE In the following countries automatic reclosing of protection means
    // is not allowed: DK, UK, FR, CH.
    relaisHealthy = true;
    switchOff();
    relaisOn = false;
}
