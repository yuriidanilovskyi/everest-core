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

PowerSwitch::PowerSwitch() {
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
        EVLOG_info << "relays not healthy";
    }
    // printf("Powerswitch initialized: %i\n", relaisHealthy);
}

PowerSwitch::~PowerSwitch() {
    switchOff();
}

bool PowerSwitch::isOn() {
    return relaisOn;
}

bool PowerSwitch::switchOnSinglePhase() {

    if (relaisHealthy) {
        Everest::Utils::sysfs_write_string(relay_1_path, "1");
        Everest::Utils::sysfs_write_string(relay_2_path, "0");

        std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));
        relaisOn = true;
        // TODO: no hardware support?
        // setPWML1(relaisHoldingPercent);
        // setPWML2L3(0);

        auto relay_1_sense = Everest::Utils::sysfs_read_string(relay_1_sense_path);
        auto relay_2_sense = Everest::Utils::sysfs_read_string(relay_2_sense_path);

        EVLOG_info << "switchOnSinglePhase, relay_1_sense: " << relay_1_sense << " relay_2_sense: " << relay_2_sense;
        // FIXME: is this assumption correct?
        if (relay_1_sense == "0" && relay_2_sense == "0")
            relaisHealthy = true;
        else
            relaisHealthy = false;
    }
    return relaisHealthy;
}

bool PowerSwitch::switchOnThreePhase() {
    if (relaisHealthy) {
        Everest::Utils::sysfs_write_string(relay_1_path, "1");
        Everest::Utils::sysfs_write_string(relay_2_path, "1");

        std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));
        relaisOn = true;
        // TODO: no hardware support?

        // setPWML1(relaisHoldingPercent);
        // setPWML2L3(relaisHoldingPercent);

        auto relay_1_sense = Everest::Utils::sysfs_read_string(relay_1_sense_path);
        auto relay_2_sense = Everest::Utils::sysfs_read_string(relay_2_sense_path);

        EVLOG_info << "switchOnThreePhase, relay_1_sense: " << relay_1_sense << " relay_2_sense: " << relay_2_sense;
        // FIXME: is this assumption correct?
        if (relay_1_sense == "0" && relay_2_sense == "0")
            relaisHealthy = true;
        else
            relaisHealthy = false;
    }
    return relaisHealthy;
}

bool PowerSwitch::switchOff() {
    Everest::Utils::sysfs_write_string(relay_1_path, "0");
    Everest::Utils::sysfs_write_string(relay_2_path, "0");

    // TODO sensing
    std::this_thread::sleep_for(std::chrono::milliseconds(relaisDelay));
    auto relay_1_sense = Everest::Utils::sysfs_read_string(relay_1_sense_path);
    auto relay_2_sense = Everest::Utils::sysfs_read_string(relay_2_sense_path);

    // FIXME: relaisHealthy when relay_1_sense and relay_2_sense are 0 ?
    relaisOn = false;
    if (relay_1_sense == "0" && relay_2_sense == "0")
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
