// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#ifndef ENERGY_GRID_ENERGY_IMPL_HPP
#define ENERGY_GRID_ENERGY_IMPL_HPP

//
// AUTO GENERATED - MARKED REGIONS WILL BE KEPT
// template version 3
//

#include <generated/interfaces/energy/Implementation.hpp>

#include "../EvseManager.hpp"

// ev@75ac1216-19eb-4182-a85c-820f1fc2c091:v1
#include "utils/thread.hpp"
// ev@75ac1216-19eb-4182-a85c-820f1fc2c091:v1

namespace module {
namespace energy_grid {

struct Conf {};

class energyImpl : public energyImplBase {
public:
    energyImpl() = delete;
    energyImpl(Everest::ModuleAdapter* ev, const Everest::PtrContainer<EvseManager>& mod, Conf& config) :
        energyImplBase(ev, "energy_grid"), mod(mod), config(config){};

    // ev@8ea32d28-373f-4c90-ae5e-b4fcc74e2a61:v1
    // insert your public definitions here
    // ev@8ea32d28-373f-4c90-ae5e-b4fcc74e2a61:v1

protected:
    // command handler functions (virtual)
    virtual void handle_enforce_limits(std::string& uuid, types::energy::Limits& limits_import,
                                       types::energy::Limits& limits_export,
                                       std::vector<types::energy::TimeSeriesEntry>& schedule_import,
                                       std::vector<types::energy::TimeSeriesEntry>& schedule_export) override;

    // ev@d2d1847a-7b88-41dd-ad07-92785f06f5c4:v1
    // insert your protected definitions here
    // ev@d2d1847a-7b88-41dd-ad07-92785f06f5c4:v1

private:
    const Everest::PtrContainer<EvseManager>& mod;
    const Conf& config;

    virtual void init() override;
    virtual void ready() override;

    // ev@3370e4dd-95f4-47a9-aaec-ea76f34a66c9:v1
    std::mutex energy_mutex;
    double _price_limit;
    double _price_limit_previous_value;
    std::string _optimizer_mode;
    double _manual_current_limit_A;
    json energy;

    void initializeEnergyObject();
    void updateAndPublishEnergyObject();
    // ev@3370e4dd-95f4-47a9-aaec-ea76f34a66c9:v1
};

// ev@3d7da0ad-02c2-493d-9920-0bbbd56b9876:v1
// insert other definitions here
#define EVSE_OPTIMIZER_MODE_MANUAL_LIMITS std::string("manual_limits")
#define EVSE_OPTIMIZER_MODE_PRICE_DRIVEN  std::string("price_driven")
// ev@3d7da0ad-02c2-493d-9920-0bbbd56b9876:v1

} // namespace energy_grid
} // namespace module

#endif // ENERGY_GRID_ENERGY_IMPL_HPP
