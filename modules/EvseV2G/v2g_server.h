// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest
#ifndef V2G_SERVER_H
#define V2G_SERVER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "v2g.h"

/*!
 * \brief v2g_handle_connection This function handles a v2g-charging-session.
 * \param conn hold the context of the v2g-connection.
 * \return Returns 0 if the v2g-session was successfully stopped, otherwise -1.
 */
int v2g_handle_connection(struct v2g_connection *conn);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* V2G_SERVER_H */
