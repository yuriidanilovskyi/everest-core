// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include "iso_server.hpp"

enum v2g_event iso_handle_request(v2g_connection *conn) {
	//TODO: handle ISO request
	return V2G_EVENT_TERMINATE_CONNECTION;
}
