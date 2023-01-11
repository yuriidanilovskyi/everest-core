// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <openv2g/v2gtp.h>
#include <openv2g/appHandEXIDatatypesEncoder.h>
#include <openv2g/appHandEXIDatatypesDecoder.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include "v2g_server.hpp"
#include "log.hpp"
#include "connection.hpp"
#include "tools.hpp"

/*!
 * \brief v2g_incoming_v2gtp This function reads the v2g transport header
 * \param conn hold the context of the v2g-connection.
 * \return Returns 0 if the v2g-session was successfully stopped, otherwise -1.
 */
static int v2g_incoming_v2gtp(struct v2g_connection *conn) {
    int rv;

    /* read and process header */
    rv = connection_read(conn, conn->buffer, V2GTP_HEADER_LENGTH);
    if (rv < 0) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(header) failed: %s", (rv == -1)? strerror(errno) : "connection terminated");
        return -1;
    }
    /* peer closed connection */
    if (rv == 0)
        return 1;
    if (rv != V2GTP_HEADER_LENGTH) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(header) too short: expected %d, got %d", V2GTP_HEADER_LENGTH, rv);
        return -1;
    }

    rv = read_v2gtpHeader(conn->buffer, &conn->payload_len);
    if (rv == -1) {
        dlog(DLOG_LEVEL_ERROR, "invalid v2gtp header");
        return -1;
    }

    if (conn->payload_len + V2GTP_HEADER_LENGTH > DEFAULT_BUFFER_SIZE) {
        dlog(DLOG_LEVEL_ERROR, "payload too long: have %d, would need %d", DEFAULT_BUFFER_SIZE, conn->payload_len + V2GTP_HEADER_LENGTH);

        /* we have no way to flush/discard remaining unread data from the socket without reading it in chunks,
         * but this opens the chance to bind us in a "endless" read loop; so to protect us, simply close the connection
         */

        return -1;
    }
    /* read request */
    rv = connection_read(conn, &conn->buffer[V2GTP_HEADER_LENGTH], conn->payload_len);
    if (rv < 0) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(payload) failed: %s", (rv == -1)? strerror(errno) : "connection terminated");
        return -1;
    }
    if (rv != conn->payload_len) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(payload) too short: expected %d, got %d", conn->payload_len, rv);
        return -1;
    }
    /* adjust buffer pos to decode request */
    conn->buffer_pos = V2GTP_HEADER_LENGTH;
    conn->stream.size = conn->payload_len + V2GTP_HEADER_LENGTH;

    /* optionally dump packet into file for later analysis */
    // TODO: v2g_dump_packet(conn);

    return 0;
}

/*!
 * \brief v2g_outgoing_v2gtp This function creates the v2g transport header
 * \param conn hold the context of the v2g-connection.
 * \return Returns 0 if the v2g-session was successfully stopped, otherwise -1.
 */
int v2g_outgoing_v2gtp(struct v2g_connection *conn) {
	/* fixup/create header */
	if (write_v2gtpHeader(conn->buffer, conn->buffer_pos - V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE) != 0) {
		dlog(DLOG_LEVEL_ERROR, "write_v2gtpHeader() failed");
		return -1;
	}

	if (connection_write(conn, conn->buffer, conn->buffer_pos) == -1) {
		dlog(DLOG_LEVEL_ERROR, "connection_write(header) failed: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int v2g_handle_connection(struct v2g_connection *conn) {
	return -1; // TODO: Implement v2g connection message handler
}
