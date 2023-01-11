// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#ifndef DIN_SERVER_HPP
#define DIN_SERVER_HPP

#include "din_server.hpp"

/*!
 * \brief din_handle_request This function handles the incoming request message of a connected ev.
 *  It analyzes the incoming din request EXI stream and configures the response EXI stream
 * \param conn This structure provides the EXI streams
 * \return This function returns \c 1 if the connection needs to be aborted without sending the reply,
 *  it returns \c 0 if the req handle was successful, it returns \c 1 if the reply needs to be sent and the connection needs to be closed afterwards,
 *  \c -1 if the connection must be closed immediately and it returns \c 2 if no reply needs to be send but the connection must be kept opened.
 */
enum v2g_event din_handle_request(v2g_connection *conn);

#endif /* DIN_SERVER_HPP */
