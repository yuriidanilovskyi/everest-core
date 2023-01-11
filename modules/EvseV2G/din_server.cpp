// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include "v2g.hpp"

enum v2g_event din_handle_request(v2g_connection *conn) {
	//TODO: handle DIN request
	return V2G_EVENT_TERMINATE_CONNECTION;
}
