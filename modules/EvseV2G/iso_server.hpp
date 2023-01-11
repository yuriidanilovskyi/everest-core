// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#ifndef ISO_SERVER_HPP
#define ISO_SERVER_HPP

#include "v2g.hpp"

/*!
 * \brief iso_handle_request This is the main protocol handler. This function analyzes the received
 *  request msg and configures the next response msg.
 * \param conn \c v2g_connection struct and holds the v2g_connection information
 * \return when this function returns -1 then the connection is aborted without sending the reply,
 *  when this function returns 0 then the reply is sent,
 *  when this function returns 1 then the reply is sent and the connection is closed afterwards,
 *  when this function returns 2 then no reply is sent but the connection is kept open
 */
enum v2g_event iso_handle_request(v2g_connection *conn);

#endif /* ISO_SERVER_HPP */
