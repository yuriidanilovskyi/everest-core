// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <openv2g/v2gtp.h>
#include <openv2g/appHandEXIDatatypesEncoder.h>
#include <openv2g/appHandEXIDatatypesDecoder.h>
#include <openv2g/dinEXIDatatypes.h>
#include <openv2g/dinEXIDatatypesEncoder.h>
#include <openv2g/dinEXIDatatypesDecoder.h>
#include <openv2g/iso1EXIDatatypes.h>
#include <openv2g/iso1EXIDatatypesEncoder.h>
#include <openv2g/iso1EXIDatatypesDecoder.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "v2g_server.hpp"
#include "din_server.hpp"
#include "iso_server.hpp"
#include "log.hpp"
#include "connection.hpp"
#include "tools.hpp"

#define MAX_RES_TIME 98

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

/*!
 * \brief v2g_handle_apphandshake After receiving a supportedAppProtocolReq message,
 * the SECC shall process the received information. DIN [V2G-DC-436] ISO [V2G2-540]
 * \param conn hold the context of the v2g-connection.
 * \return Returns a v2g-event of type enum v2g_event.
 */
static enum v2g_event v2g_handle_apphandshake(struct v2g_connection *conn)
{
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;
    int i;
    uint8_t ev_app_priority = 20; // lowest priority

    /* validate handshake request and create response */
    init_appHandEXIDocument(&conn->handshake_resp);
    conn->handshake_resp.supportedAppProtocolRes_isUsed = 1;
    conn->handshake_resp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_Failed_NoNegotiation; // [V2G2-172]

    dlog(DLOG_LEVEL_INFO, "Handling SupportedAppProtocolReq");
    conn->ctx->current_v2g_msg = V2G_SUPPORTED_APP_PROTOCOL_MSG;

    if (decode_appHandExiDocument(&conn->stream, &conn->handshake_req) != 0) {
        dlog(DLOG_LEVEL_ERROR, "decode_appHandExiDocument() failed");
        return V2G_EVENT_TERMINATE_CONNECTION; // If the mesage can't be decoded we have to terminate the tcp-connection (e.g. after an unexpected message)
    }

    for (i = 0; i < conn->handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen ; i++) {
        struct appHandAppProtocolType *app_proto = &conn->handshake_req.supportedAppProtocolReq.AppProtocol.array[i];
        char *proto_ns = strndup((const char *)app_proto->ProtocolNamespace.characters, app_proto->ProtocolNamespace.charactersLen);

        if (!proto_ns) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory condition");
            return V2G_EVENT_TERMINATE_CONNECTION;
        }

        dlog(DLOG_LEVEL_TRACE, "handshake_req: Namespace: %s, Version: %" PRIu32 ".%" PRIu32 ", SchemaID: %" PRIu8 ", Priority: %" PRIu8,
             proto_ns, app_proto->VersionNumberMajor, app_proto->VersionNumberMinor, app_proto->SchemaID, app_proto->Priority);

        if ((conn->ctx->supported_protocols & (1 << V2G_PROTO_DIN70121)) && (strcmp(proto_ns, DIN_70121_MSG_DEF) == 0) &&
                (app_proto->VersionNumberMajor == DIN_70121_MAJOR) && (ev_app_priority >= app_proto->Priority)) {
            conn->handshake_resp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiation;
            ev_app_priority = app_proto->Priority;
            conn->handshake_resp.supportedAppProtocolRes.SchemaID = app_proto->SchemaID;
            conn->ctx->selected_protocol = V2G_PROTO_DIN70121;
        }
        else if ((conn->ctx->supported_protocols & (1 << V2G_PROTO_ISO15118_2013)) && (strcmp(proto_ns, ISO_15118_2013_MSG_DEF) == 0) &&
                 (app_proto->VersionNumberMajor == ISO_15118_2013_MAJOR) && (ev_app_priority >= app_proto->Priority)) {

            conn->handshake_resp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiation;
            ev_app_priority = app_proto->Priority;
            conn->handshake_resp.supportedAppProtocolRes.SchemaID = app_proto->SchemaID;
            conn->ctx->selected_protocol = V2G_PROTO_ISO15118_2013;
        }

        // TODO: ISO15118v2

        free(proto_ns);
    }

    if (conn->handshake_resp.supportedAppProtocolRes.ResponseCode == appHandresponseCodeType_OK_SuccessfulNegotiation) {
        conn->handshake_resp.supportedAppProtocolRes.SchemaID_isUsed = (unsigned int) 1;
        if (V2G_PROTO_DIN70121 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is DIN70121");

            // Configure DIN 70121 protocol specific configuration
            if (conn->ctx->evse_charging_type == CHARGING_TYPE_FAKE_HLC) {
                /* Configure not standard conform three-phase AC transfer mode to force a charge abort by the EV,
                   because the re-init mechanism, as described in ISO 15118, is not part of the DIN 70121 standard.*/
                conn->ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0] = iso1EnergyTransferModeType_AC_three_phase_core;
            }
        }
        else if (V2G_PROTO_ISO15118_2013 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is ISO15118");
        }
        else if (V2G_PROTO_ISO15118_2010 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is ISO15118-2010");
        }
    }
    else {
        dlog(DLOG_LEVEL_ERROR, "No compatible protocol found");
        next_event = V2G_EVENT_SEND_AND_TERMINATE; // Send response and terminate tcp-connection
    }

    if (true == conn->ctx->is_connection_terminated) {
        dlog(DLOG_LEVEL_ERROR, "Connection is terminated. Abort charging");
        return V2G_EVENT_TERMINATE_CONNECTION; // Abort charging without sending a response
    }

    /* Validate response code */
    if ((true == conn->ctx->intl_emergency_shutdown) ||
            (true == conn->ctx->stop_hlc) || (V2G_EVENT_SEND_AND_TERMINATE == next_event)) {
        conn->handshake_resp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_Failed_NoNegotiation;
        dlog(DLOG_LEVEL_ERROR, "Abort charging session");
        next_event = V2G_EVENT_SEND_AND_TERMINATE; // send response and terminate the tcp-connection
    }

    /* encode response at the right buffer location */
    *(conn->stream.pos) = V2GTP_HEADER_LENGTH;
    conn->stream.capacity = 8; // as it should be for send
    conn->stream.buffer = 0;

    if (0 != encode_appHandExiDocument(&conn->stream, &conn->handshake_resp)) {
        dlog(DLOG_LEVEL_ERROR, "Encoding of the protocol handshake message failed");
        next_event = V2G_EVENT_SEND_AND_TERMINATE;
    }

    return next_event;
}

int v2g_handle_connection(struct v2g_connection *conn) {
    int rv = -1;
    enum v2g_event rvAppHandshake = V2G_EVENT_NO_EVENT;
	bool stop_receiving_loop = false;
    int64_t start_time = 0; // in ms

    enum v2g_protocol selected_protocol = V2G_UNKNOWN_PROTOCOL;
    v2g_ctx_init_charging_state(conn->ctx, false);
    conn->buffer = (uint8_t *)malloc(DEFAULT_BUFFER_SIZE);
    if (!conn->buffer)
        return -1;

    /* static setup */
    conn->stream.data = conn->buffer;
    conn->stream.pos = &conn->buffer_pos;

    /* Here is a good point to wait until the customer is ready for a resumed session,
     * because we are waiting for the incoming message of the ev */
    if (conn->dlink_action == MQTT_DLINK_ACTION_PAUSE) {
        // TODO: D_LINK pause
    }

    do {
        /* setup for receive */
        conn->stream.buffer = 0;
        conn->stream.capacity = 0; // Set to 8 for send and 0 for recv
        conn->buffer_pos = 0;
        conn->payload_len = 0;

        /* next call return -1 on error, 1 when peer closed connection, 0 on success */
        rv = v2g_incoming_v2gtp(conn);

        if (rv != 0) {
            dlog(DLOG_LEVEL_ERROR, "v2g_incoming_v2gtp() failed");
            goto error_out;
        }

        if(conn->ctx->is_connection_terminated == true) {
            rv = -1;
            goto error_out;
        }

        /* next call return -1 on non-recoverable errors, 1 on recoverable errors, 0 on success */
        rvAppHandshake = v2g_handle_apphandshake(conn);

        if (rvAppHandshake == V2G_EVENT_IGNORE_MSG) {
            dlog(DLOG_LEVEL_WARNING, "v2g_handle_apphandshake() failed, ignoring packet");
        }
    } while ((rv == 1) && (rvAppHandshake == V2G_EVENT_IGNORE_MSG));

    /* stream setup for sending is done within v2g_handle_apphandshake */
    /* send supportedAppRes message */
    if ((rvAppHandshake == V2G_EVENT_SEND_AND_TERMINATE) ||
            (rvAppHandshake == V2G_EVENT_NO_EVENT)) {
        rv = v2g_outgoing_v2gtp(conn);

        if (rv == -1) {
            dlog(DLOG_LEVEL_ERROR, "v2g_outgoing_v2gtp() failed");
            goto error_out;
        }
    }

    /* terminate connection, if supportedApp handshake has failed */
    if ((rvAppHandshake == V2G_EVENT_SEND_AND_TERMINATE)  ||
            (rvAppHandshake == V2G_EVENT_TERMINATE_CONNECTION)) {
        rv = -1;
        goto error_out;
    }

    /* Backup the selected protocol, because this value is shared and can be reseted while unplugging. */
    selected_protocol = conn->ctx->selected_protocol;

	/* allocate in/out documents dynamically */
	switch (selected_protocol) {
		case V2G_PROTO_DIN70121:
		case V2G_PROTO_ISO15118_2010:
			conn->exi_in.dinEXIDocument = (struct dinEXIDocument *)calloc(1, sizeof(struct dinEXIDocument));
			if (conn->exi_in.dinEXIDocument == NULL) {
				dlog(DLOG_LEVEL_ERROR, "out-of-memory");
				goto error_out;
			}
			conn->exi_out.dinEXIDocument = (struct dinEXIDocument *)calloc(1, sizeof(struct dinEXIDocument));
			if (conn->exi_out.dinEXIDocument == NULL) {
				dlog(DLOG_LEVEL_ERROR, "out-of-memory");
				goto error_out;
			}
			break;
		case V2G_PROTO_ISO15118_2013:
			conn->exi_in.iso1EXIDocument = (struct iso1EXIDocument *)calloc(1, sizeof(struct iso1EXIDocument));
			if (conn->exi_in.iso1EXIDocument == NULL) {
				dlog(DLOG_LEVEL_ERROR, "out-of-memory");
				goto error_out;
			}
			conn->exi_out.iso1EXIDocument = (struct iso1EXIDocument *)calloc(1, sizeof(struct iso1EXIDocument));
			if (conn->exi_out.iso1EXIDocument == NULL) {
				dlog(DLOG_LEVEL_ERROR, "out-of-memory");
				goto error_out;
			}
			break;
		default:
			goto error_out; // 	if protocol is unknown
	}

	do {
		/* setup for receive */
		conn->stream.buffer = 0;
		conn->stream.capacity = 0; // Set to 8 for send and 0 for recv
		conn->buffer_pos = 0;
		conn->payload_len = 0;

		/* next call return -1 on error, 1 when peer closed connection, 0 on success */
		rv = v2g_incoming_v2gtp(conn);

		if (rv == 1) {
			dlog(DLOG_LEVEL_ERROR, "timeout waiting for next request or peer closed connection");
			break;
		}
		else if (rv == -1) {
			dlog(DLOG_LEVEL_ERROR, "v2g_incoming_v2gtp() (previous message \"%s\") failed", v2gMsgType[conn->ctx->last_v2g_msg]);
			break;
		}

		start_time = getmonotonictime(); // To calc the duration of req msg configuration

		/* according to agreed protocol decode the stream */
		enum v2g_event v2gEvent = V2G_EVENT_NO_EVENT;
		switch (selected_protocol) {
			case V2G_PROTO_DIN70121:
			case V2G_PROTO_ISO15118_2010:
				memset(conn->exi_in.dinEXIDocument, 0, sizeof(struct dinEXIDocument));
				rv = decode_dinExiDocument(&conn->stream, conn->exi_in.dinEXIDocument);
				if (rv != 0) {
					dlog(DLOG_LEVEL_ERROR, "decode_dinExiDocument() (previous message \"%s\") failed: %d", v2gMsgType[conn->ctx->last_v2g_msg], rv);
					/* we must ignore packet which we cannot decode, so reset rv to zero to stay in loop */
					rv = 0;
					v2gEvent = V2G_EVENT_IGNORE_MSG;
					break;
				}

				memset(conn->exi_out.dinEXIDocument, 0, sizeof(struct dinEXIDocument));
				conn->exi_out.dinEXIDocument->V2G_Message_isUsed = 1;

				v2gEvent = din_handle_request(conn);
				break;

			case V2G_PROTO_ISO15118_2013:
				memset(conn->exi_in.iso1EXIDocument, 0, sizeof(struct iso1EXIDocument));
				rv = decode_iso1ExiDocument(&conn->stream, conn->exi_in.iso1EXIDocument);
				if (rv != 0) {
					dlog(DLOG_LEVEL_ERROR, "decode_iso1EXIDocument() (previous message \"%s\") failed: %d", v2gMsgType[conn->ctx->last_v2g_msg], rv);
					/* we must ignore packet which we cannot decode, so reset rv to zero to stay in loop */
					rv = 0;
					v2gEvent = V2G_EVENT_IGNORE_MSG;
					break;
				}
				conn->buffer_pos = 0; // Reset buffer pos for the case if exi msg will be configured over mqtt
				memset(conn->exi_out.iso1EXIDocument, 0, sizeof(struct iso1EXIDocument));
				conn->exi_out.iso1EXIDocument->V2G_Message_isUsed = 1;

				v2gEvent = iso_handle_request(conn);

				break;
			default:
				goto error_out; // 	if protocol is unknown
		}

		switch(v2gEvent) {
			case V2G_EVENT_SEND_AND_TERMINATE:
				stop_receiving_loop = true;
			case V2G_EVENT_NO_EVENT: {// fall-through intended
				/* Reset v2g-buffer */
				conn->stream.buffer = 0;
				conn->stream.capacity = 8; // Set to 8 for send and 0 for recv
				conn->buffer_pos = V2GTP_HEADER_LENGTH;
				conn->stream.size = DEFAULT_BUFFER_SIZE;

				/* Configure msg and send */
				switch (selected_protocol) {
					case V2G_PROTO_DIN70121:
					case V2G_PROTO_ISO15118_2010:
						if ((rv = encode_dinExiDocument(&conn->stream, conn->exi_out.dinEXIDocument)) != 0) {
							dlog(DLOG_LEVEL_ERROR, "encode_dinExiDocument() (message \"%s\") failed: %d", v2gMsgType[conn->ctx->current_v2g_msg], rv);
						}
						break;
					case V2G_PROTO_ISO15118_2013:
						if ((rv = encode_iso1ExiDocument(&conn->stream, conn->exi_out.iso1EXIDocument)) != 0) {
							dlog(DLOG_LEVEL_ERROR, "encode_iso1ExiDocument() (message \"%s\") failed: %d", v2gMsgType[conn->ctx->current_v2g_msg], rv);
						}
						break;
					default:
						goto error_out; // 	if protocol is unknown
				}
				/* Wait max. res-time before sending the next response */
				int64_t time_to_conf_res = getmonotonictime() - start_time;

				if(time_to_conf_res < MAX_RES_TIME) {
					//dlog(DLOG_LEVEL_ERROR,"time_to_conf_res %llu", time_to_conf_res);
					usleep((MAX_RES_TIME - time_to_conf_res) * 1000);
				}
				else {
					dlog(DLOG_LEVEL_WARNING, "Response message (type %d) not configured within %d ms (took %" PRIi64 " ms)",
						 conn->ctx->current_v2g_msg, MAX_RES_TIME, time_to_conf_res);
				}
			}
			case V2G_EVENT_SEND_RECV_EXI_MSG: // fall-through intended
				/* Write header and send next res-msg */
				if ((rv != 0) || ((rv = v2g_outgoing_v2gtp(conn)) == -1)) {
					dlog(DLOG_LEVEL_ERROR, "v2g_outgoing_v2gtp() \"%s\" failed: %d", v2gMsgType[conn->ctx->current_v2g_msg], rv);
					break;
				}
				break;
			case V2G_EVENT_IGNORE_MSG:
				dlog(DLOG_LEVEL_ERROR, "Ignoring V2G request message \"%s\". Waiting for next request", v2gMsgType[conn->ctx->current_v2g_msg]);
				break;
			case V2G_EVENT_TERMINATE_CONNECTION: // fall-through intended
			default:
				dlog(DLOG_LEVEL_ERROR, "Failed to handle V2G request message \"%s\"", v2gMsgType[conn->ctx->current_v2g_msg]);
				stop_receiving_loop = true;
				break;
		}
	}
	while ((rv == 0) && (stop_receiving_loop == false));

error_out:
    switch (selected_protocol) {
        case V2G_PROTO_DIN70121:
        case V2G_PROTO_ISO15118_2010:
        	if (conn->exi_in.dinEXIDocument != NULL)
                free(conn->exi_in.dinEXIDocument);
        	if (conn->exi_out.dinEXIDocument != NULL)
        	    free(conn->exi_out.dinEXIDocument);
            break;
        case V2G_PROTO_ISO15118_2013:
        	if (conn->exi_in.iso1EXIDocument != NULL)
        	    free(conn->exi_in.iso1EXIDocument);
        	if (conn->exi_out.iso1EXIDocument != NULL)
                free(conn->exi_out.iso1EXIDocument);
            break;
        default:
            break;
    }

    if (conn->buffer != NULL) {
        free(conn->buffer);
    }

    v2g_ctx_init_charging_state(conn->ctx, true);

    return rv ? -1 : 0;
}
