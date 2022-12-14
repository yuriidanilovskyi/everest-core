/*
 * ControlPilot_HAL.cpp
 *
 *  Created on: 15.10.2021
 *      Author: cornelius
 *
 */

#include "ControlPilot_HAL.hpp"
#include "utils.hpp"
#include <everest/logging.hpp>

#include <boost/range/iterator_range.hpp>
#include <fstream>
#include <math.h>
#include <string.h>
#include <thread>

ControlPilot_HAL::ControlPilot_HAL() :
    cpLo(0), cpHi(0), min_phase_count(1), max_phase_count(1), min_current_a(6), max_current_a(6) {
    std::ofstream gpio_export("/sys/class/gpio/export");
    gpio_export << "139" << std::endl; // negative peak reset
    gpio_export << "138" << std::endl; // positive peak reset
    gpio_export << "13" << std::endl;  // CP invert
    gpio_export << "22" << std::endl;  // rotary switch 2 pin 1
    gpio_export << "23" << std::endl;  // rotary switch 2 pin 2
    gpio_export << "24" << std::endl;  // rotary switch 2 pin 4
    gpio_export << "128" << std::endl; // rotary switch 2 pin 8
    gpio_export << "76" << std::endl;  // relay 1
    gpio_export << "77" << std::endl;  // relay 2
    gpio_export << "131" << std::endl; // relay 1 sense
    gpio_export << "130" << std::endl; // relay 2 sense
    gpio_export.close();

    std::ofstream pwmchip7_export("/sys/class/pwm/pwmchip7/export");
    pwmchip7_export << "0" << std::endl; // CP PWM
    pwmchip7_export.close();

    auto gpio13_direction_path = boost::filesystem::path("/sys/class/gpio/gpio13/direction");
    Everest::Utils::wait_until_exists_exception(gpio13_direction_path, std::chrono::milliseconds(200));

    Everest::Utils::sysfs_write_string(gpio13_direction_path, "out"); // configure gpio13 as "out"

    auto pwm0 = boost::filesystem::path("/sys/class/pwm/pwmchip7/pwm0");
    Everest::Utils::wait_until_exists_exception(pwm0, std::chrono::milliseconds(200));

    // find adc device by name
    for (auto entry : boost::filesystem::directory_iterator(boost::filesystem::path("/sys/bus/iio/devices"))) {
        auto name_path = entry.path() / "name";
        if (boost::filesystem::exists(name_path)) {
            std::string iio_device_name = Everest::Utils::sysfs_read_string(name_path);

            // TODO: move adc name into config
            if (iio_device_name == std::string("2198000.adc")) {
                this->adc_device_path = entry.path();
                break;
            }
        }
    }

    if (this->adc_device_path.empty()) {
        EVLOG_error << "ADC device not found, this should probably be an exception: " << adc_device_path.string();
    }

    // get max phase count and current
    auto rotary_switch_2_pin_1_path = boost::filesystem::path("/sys/class/gpio/gpio22/value");
    Everest::Utils::wait_until_exists_exception(rotary_switch_2_pin_1_path, std::chrono::milliseconds(200));

    auto rotary_switch_2_pin_2_path = boost::filesystem::path("/sys/class/gpio/gpio23/value");
    Everest::Utils::wait_until_exists_exception(rotary_switch_2_pin_2_path, std::chrono::milliseconds(200));

    auto rotary_switch_2_pin_4_path = boost::filesystem::path("/sys/class/gpio/gpio24/value");
    Everest::Utils::wait_until_exists_exception(rotary_switch_2_pin_4_path, std::chrono::milliseconds(200));

    auto rotary_switch_2_pin_8_path = boost::filesystem::path("/sys/class/gpio/gpio128/value");
    Everest::Utils::wait_until_exists_exception(rotary_switch_2_pin_8_path, std::chrono::milliseconds(200));

    auto rotary_switch_2_pin_1 = Everest::Utils::sysfs_read_string(rotary_switch_2_pin_1_path);
    auto rotary_switch_2_pin_2 = Everest::Utils::sysfs_read_string(rotary_switch_2_pin_2_path);
    auto rotary_switch_2_pin_4 = Everest::Utils::sysfs_read_string(rotary_switch_2_pin_4_path);
    auto rotary_switch_2_pin_8 = Everest::Utils::sysfs_read_string(rotary_switch_2_pin_8_path);

    auto rotary_switch_2 =
        rotary_switch_2_pin_1 + rotary_switch_2_pin_2 + rotary_switch_2_pin_4 + rotary_switch_2_pin_8;
    auto sw2_position = "0";
    if (rotary_switch_2 == "1111") {
        sw2_position = "0";
        max_current_a = 6;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "1110") {
        sw2_position = "1";
        max_current_a = 10;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "0111") {
        sw2_position = "2";
        max_current_a = 13;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "0110") {
        sw2_position = "3";
        max_current_a = 16;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "1011") {
        sw2_position = "4";
        max_current_a = 20;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "1010") {
        sw2_position = "5";
        max_current_a = 32;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "0011") {
        sw2_position = "6";
        max_current_a = 40;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "0010") {
        sw2_position = "7";
        max_current_a = 63;
        max_phase_count = 1;
    } else if (rotary_switch_2 == "1101") {
        sw2_position = "8";
        max_current_a = 6;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "1100") {
        sw2_position = "9";
        max_current_a = 10;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "0101") {
        sw2_position = "A";
        max_current_a = 13;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "0100") {
        sw2_position = "B";
        max_current_a = 16;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "1001") {
        sw2_position = "C";
        max_current_a = 20;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "1000") {
        sw2_position = "D";
        max_current_a = 32;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "0001") {
        sw2_position = "E";
        max_current_a = 40;
        max_phase_count = 3;
    } else if (rotary_switch_2 == "0000") {
        sw2_position = "F";
        max_current_a = 63;
        max_phase_count = 3;
    }

    EVLOG_info << "SW2 position: " << sw2_position << ", max current: " << max_current_a
               << " A, max phase count: " << max_phase_count;

    disableCP();
}

ControlPilot_HAL::~ControlPilot_HAL() {
    disableCP();
}

void ControlPilot_HAL::setPWM(float dc) {
    // EVLOG_info << "Setting PWM dc: " << dc;
    uint32_t duty_cycle = dc * 1000000;
    // EVLOG_info << "Setting duty_cycle: " << duty_cycle << " that's " << duty_cycle / 10000 << " % ";
    std::ofstream pwm0_duty_cycle("/sys/class/pwm/pwmchip7/pwm0/duty_cycle");
    pwm0_duty_cycle << std::to_string(duty_cycle) << std::endl;
    pwm0_duty_cycle.close();

    std::ofstream pwm0_enable("/sys/class/pwm/pwmchip7/pwm0/enable");
    pwm0_enable << "1" << std::endl;
    pwm0_enable.close();

    std::ofstream cp_invert_line("/sys/class/gpio/gpio13/value");
    cp_invert_line << "1" << std::endl; // enable invert line
    cp_invert_line.close();
}

// function to convert the ADC output value "a" into voltage scaled to ADC reference in mV
float ControlPilot_HAL::f1(float a) {
    return a * 3300.0 / 4095.0;
}

// function to convert the voltage scaled to ADC reference "s" into CP voltage inmV
float ControlPilot_HAL::f2(float s) {
    return 9.581933 * s - 16013.855;
}

// reads ADC values for lo and hi part of PWM
// returns false if signal is unstable
bool ControlPilot_HAL::readCPSignal() {
    std::ofstream negative_peak_reset("/sys/class/gpio/gpio139/value");
    std::ofstream positive_peak_reset("/sys/class/gpio/gpio138/value");
    negative_peak_reset << "1" << std::endl; // assert reset for negative peak detector
    positive_peak_reset << "1" << std::endl; // assert reset for positive peak detector
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    negative_peak_reset << "0" << std::endl; // deassert reset for negative peak detector
    positive_peak_reset << "0" << std::endl; // deassert reset for positive peak detector
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    negative_peak_reset.close();
    positive_peak_reset.close();

    auto negative_peak_adc_path = this->adc_device_path / "in_voltage3_raw";
    auto positive_peak_adc_path = this->adc_device_path / "in_voltage2_raw";

    auto v_negative_str = Everest::Utils::sysfs_read_string(negative_peak_adc_path);
    auto v_positive_str = Everest::Utils::sysfs_read_string(positive_peak_adc_path);

    float a_negative = Everest::Utils::sysfs_read_float(negative_peak_adc_path);
    auto s_negative = f1(a_negative);
    auto v_negative = f2(s_negative);

    float a_positive = Everest::Utils::sysfs_read_float(positive_peak_adc_path);
    auto s_positive = f1(a_positive);
    auto v_positive = f2(s_positive);

    // EVLOG_info << "v_negative: " << v_negative << " mV";
    // EVLOG_info << "v_positive: " << v_positive << " mV";

    // FIXME: I assume cpLo and cpHi are in Volt, so convert them here
    cpLo = v_negative / 1000.0;
    cpHi = v_positive / 1000.0;
    return true;
}

void ControlPilot_HAL::enableCP() {
    // EVLOG_info << "enableCP";
    std::ofstream pwm7_period("/sys/class/pwm/pwmchip7/pwm0/period");
    pwm7_period << "1000000" << std::endl; // period
    pwm7_period.close();
}

void ControlPilot_HAL::disableCP() {
    // EVLOG_info << "disableCP";
    std::ofstream pwm0_duty_cycle("/sys/class/pwm/pwmchip7/pwm0/duty_cycle");
    pwm0_duty_cycle << "100" << std::endl; // generate 100% for at least 1 cycle for a deterministic falling edge
    std::this_thread::sleep_for(std::chrono::milliseconds(2)); // wait at least 2 ms

    std::ofstream cp_invert_line("/sys/class/gpio/gpio13/value");
    cp_invert_line << "0" << std::endl; // disable invert line
    cp_invert_line.close();

    pwm0_duty_cycle << "0" << std::endl; // 0% duty cycle
    pwm0_duty_cycle.close();
}

void ControlPilot_HAL::lockMotorUnlock() {
    // TODO
}

void ControlPilot_HAL::lockMotorLock() {
    // TODO
}

void ControlPilot_HAL::lockMotorOff() {
    // TODO
}

float ControlPilot_HAL::getCPHi() {
    return cpHi;
}

float ControlPilot_HAL::getCPLo() {
    return cpLo;
}

float ControlPilot_HAL::getSupply12V() {
    // FIXME: this does not seem to be supported by this hardware
    return 12;
}
float ControlPilot_HAL::getSupplyN12V() {
    // FIXME: this does not seem to be supported by this hardware
    return -12;
}

int32_t ControlPilot_HAL::getMinPhaseCount() {
    return min_phase_count;
}

int32_t ControlPilot_HAL::getMaxPhaseCount() {
    return max_phase_count;
}

int32_t ControlPilot_HAL::getMinCurrentA() {
    return min_current_a;
}

int32_t ControlPilot_HAL::getMaxCurrentA() {
    return max_current_a;
}
