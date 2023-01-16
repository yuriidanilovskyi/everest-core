// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
#ifndef V2G_CTX_H
#define V2G_CTX_H

#include <stdbool.h>
#include "v2g.hpp"

#define PHY_VALUE_MULT_MIN -3
#define PHY_VALUE_MULT_MAX 3
#define PHY_VALUE_VALUE_MIN SHRT_MIN
#define PHY_VALUE_VALUE_MAX SHRT_MAX

struct v2g_context *v2g_ctx_create();

/*!
 * \brief v2g_ctx_init_charging_session This funcion inits a charging session.
 * \param ctx is a pointer of type \c v2g_context. It holds the charging values.
 * \param is_connection_terminated must be set to \c true if the connection is terminated.
 */
void v2g_ctx_init_charging_session (struct v2g_context * const ctx, bool is_connection_terminated);

/*!
 * \brief init_physical_value This funcion inits a physicalValue struct.
 * \param physicalValue is the struct of the physical value.
 * \param unit is the unit of the physical value.
 */
void init_physical_value(struct iso1PhysicalValueType * const physicalValue, iso1unitSymbolType unit);

/*!
 * \brief populate_physical_value This function fills all elements of a \c iso1PhysicalValueType struct regarding the parameter value and unit.
 * \param pv is pointer to the physical value struct
 * \param value is the physical value
 * \param unit is the unit of the physical value
 * \return Returns \c true if the convertion was succesfull, otherwise \c false.
 */
bool populate_physical_value(struct iso1PhysicalValueType *pv, long long int value, iso1unitSymbolType unit);

/*!
 * \brief populate_physical_value_float This function fills all elements of a \c iso1PhysicalValueType struct from a json object.
 * \param pv is pointer to the physical value struct
 * \param value is the physical value
 * \param decimal_places is to determine the precision
 * \param unit is the unit of the physical value
 */
void populate_physical_value_float(struct iso1PhysicalValueType *pv, float value, uint8_t decimal_places, iso1unitSymbolType unit);

/*!
 * \brief setMinPhysicalValue This function sets the minimum value of ASrcPhyValue and ADstPhyValue in ADstPhyValue.
 * \param ADstPhyValue is the destination value, where the minimum value will be stored.
 * \param ASrcPhyValue is the source value, which will be compared with the ADstPhyValue value.
 * \param AIsUsed If AIsUsed is \c 0 ASrcPhyValue will be used to initialize ADstPhyValue and AIsUsed will be set to \c 1. Can be set to \c NULL
 */
void setMinPhysicalValue(struct iso1PhysicalValueType *ADstPhyValue, const struct iso1PhysicalValueType *ASrcPhyValue, unsigned int *AIsUsed);

/*!
 * \brief v2g_ctx_init_charging_state This function inits the charging state. This should be called afer a terminated charging session.
 * \param ctx is a pointer of type \c v2g_context. It holds the charging values.
 * \param is_connection_terminated is set to \c true if the connection is terminated
 */
void v2g_ctx_init_charging_state(struct v2g_context * const ctx, bool is_connection_terminated);

/*!
 * \brief init_charging_values This function inits all charge-values (din/iso). This should be called after starting the charging session.
 * \param ctx is a pointer of type \c v2g_context. It holds the charging values.
 */
void v2g_ctx_init_charging_values(struct v2g_context * const ctx);

/*!
 * \brief v2g_ctx_free
 * \param ctx
 */
void v2g_ctx_free(struct v2g_context *ctx);

/*!
 * \brief stop_timer This function stops a event timer. Note: mqtt_lock mutex must be unclocked before
 *  calling of this function.
 * \param event_timer is the event timer.
 * \param timer_name is the name of the event timer.
 */
void stop_timer(struct event ** event_timer, char const * const timer_name, struct v2g_context *ctx);

#endif /* V2G_CTX_H */