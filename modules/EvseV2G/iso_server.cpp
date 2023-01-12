// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <openv2g/iso1EXIDatatypes.h>
#include <string.h>

#include "iso_server.hpp"
#include "log.hpp"
#include "v2g_server.hpp"


//=============================================
//             Request Handling
//=============================================

/*!
 * \brief handle_iso_session_setup This function handles the iso_session_setup msg pair. It analyzes the request msg and fills the response msg.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_session_setup(struct v2g_connection *conn) {
	//TODO: implement SessionSetup handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_service_discovery This function handles the din service discovery msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_service_discovery(struct v2g_connection *conn) {
	//TODO: implement ServiceDiscovery handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_service_detail This function handles the iso_service_detail msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure. (Optional VAS)
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_service_detail(struct v2g_connection *conn) {
	//TODO: implement ServiceDetail handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_payment_service_selection This function handles the iso_payment_service_selection msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_payment_service_selection(struct v2g_connection *conn) {
	//TODO: implement PaymentServiceSelection handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_payment_details This function handles the iso_payment_details msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_payment_details(struct v2g_connection *conn) {
	//TODO: implement PaymentDetails handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_authorization This function handles the iso_authorization msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_authorization(struct v2g_connection *conn) {
	//TODO: implement Authorization handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_charge_parameter_discovery This function handles the iso_charge_parameter_discovery msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_charge_parameter_discovery(struct v2g_connection *conn) {
	//TODO: implement ChargeParameterDiscovery handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_power_delivery This function handles the iso_power_delivery msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_power_delivery(struct v2g_connection *conn) {
	//TODO: implement PowerDelivery handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_charging_status This function handles the iso_charging_status msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_charging_status(struct v2g_connection *conn) {
	//TODO: implement ChargingStatus handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_metering_receipt This function handles the iso_metering_receipt msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_metering_receipt(struct v2g_connection *conn) {
	//TODO: implement MeteringRecipt handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_certificate_update This function handles the iso_certificate_update msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_certificate_update(struct v2g_connection *conn) {
	//TODO: implement CertificateUpdate handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_certificate_installation This function handles the iso_certificate_installation msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_certificate_installation(struct v2g_connection *conn) {
	//TODO: implement CertificateInstallation handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_cable_check This function handles the iso_cable_check msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_cable_check(struct v2g_connection *conn) {
	//TODO: implement CableCheck handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_pre_charge This function handles the iso_pre_charge msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_pre_charge(struct v2g_connection *conn) {
	//TODO: implement PreCharge handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_current_demand This function handles the iso_current_demand msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_current_demand(struct v2g_connection *conn) {
	//TODO: implement CurrentDemand handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_welding_detection This function handles the iso_welding_detection msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_welding_detection(struct v2g_connection *conn) {
	//TODO: implement WeldingDetection handling
	return V2G_EVENT_NO_EVENT;
}

/*!
 * \brief handle_iso_session_stop This function handles the iso_session_stop msg pair. It analyses the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \param session_data holds the session data.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_session_stop(struct v2g_connection *conn) {
	//TODO: implement SessionStop handling
	return V2G_EVENT_NO_EVENT;
}

enum v2g_event iso_handle_request(v2g_connection *conn) {
	struct iso1EXIDocument *exi_in = conn->exi_in.iso1EXIDocument;
	struct iso1EXIDocument *exi_out = conn->exi_out.iso1EXIDocument;
	bool resume_trial;
	enum v2g_event next_v2g_event = V2G_EVENT_TERMINATE_CONNECTION;

	/* check whether we have a valid EXI document embedded within a V2G message */
	if (!exi_in->V2G_Message_isUsed) {
		dlog(DLOG_LEVEL_ERROR, "V2G_Message not used");
		return V2G_EVENT_IGNORE_MSG;
	}

	/* extract session id */
	conn->ctx->received_session_id = v2g_session_id_from_exi(true, exi_in);

	/* init V2G structure (document, header, body) */
	init_iso1EXIDocument(exi_out);
	exi_out->V2G_Message_isUsed = 1u;
	init_iso1MessageHeaderType(&exi_out->V2G_Message.Header);

	exi_out->V2G_Message.Header.SessionID.bytesLen = 8;
	init_iso1BodyType(&exi_out->V2G_Message.Body);

	/* handle each message type individually;
	 * we use a none-usual source code formatting here to optically group the individual
	 * request a little bit
	 */
	if (exi_in->V2G_Message.Body.CurrentDemandReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling CurrentDemandReq");
		conn->ctx->current_v2g_msg = V2G_CURRENT_DEMAND_MSG;
		exi_out->V2G_Message.Body.CurrentDemandRes_isUsed = 1u;
		init_iso1CurrentDemandResType(&exi_out->V2G_Message.Body.CurrentDemandRes);
		next_v2g_event = handle_iso_current_demand(conn); //  [V2G2-592]
	}
	else if (exi_in->V2G_Message.Body.SessionSetupReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling SessionSetupReq");
		conn->ctx->current_v2g_msg = V2G_SESSION_SETUP_MSG;
		exi_out->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
		init_iso1SessionSetupResType(&exi_out->V2G_Message.Body.SessionSetupRes);
		next_v2g_event = handle_iso_session_setup(conn); // [V2G2-542]
	}
	else if (exi_in->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling ServiceDiscoveryReq");
		conn->ctx->current_v2g_msg = V2G_SERVICE_DISCOVERY_MSG;
		exi_out->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
		init_iso1ServiceDiscoveryResType(&exi_out->V2G_Message.Body.ServiceDiscoveryRes);
		next_v2g_event = handle_iso_service_discovery(conn); // [V2G2-542]
	}
	else if (exi_in->V2G_Message.Body.ServiceDetailReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling ServiceDetailReq");
		conn->ctx->current_v2g_msg = V2G_SERVICE_DETAIL_MSG;
		exi_out->V2G_Message.Body.ServiceDetailRes_isUsed = 1u;
		init_iso1ServiceDetailResType(&exi_out->V2G_Message.Body.ServiceDetailRes);
		next_v2g_event = handle_iso_service_detail(conn); // [V2G2-547]
	}
	else if (exi_in->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling PaymentServiceSelectionReq");
		conn->ctx->current_v2g_msg = V2G_PAYMENT_SERVICE_SELECTION_MSG;
		exi_out->V2G_Message.Body.PaymentServiceSelectionRes_isUsed = 1u;
		init_iso1PaymentServiceSelectionResType(&exi_out->V2G_Message.Body.PaymentServiceSelectionRes);
		next_v2g_event = handle_iso_payment_service_selection(conn); // [V2G2-550]
	}
	else if (exi_in->V2G_Message.Body.PaymentDetailsReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling PaymentDetailsReq");
		conn->ctx->current_v2g_msg = V2G_PAYMENT_DETAILS_MSG;
		exi_out->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;
		init_iso1PaymentDetailsResType(&exi_out->V2G_Message.Body.PaymentDetailsRes);
		next_v2g_event = handle_iso_payment_details(conn); // [V2G2-559]
	}
	else if (exi_in->V2G_Message.Body.AuthorizationReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling AuthorizationReq");
		conn->ctx->current_v2g_msg = V2G_AUTHORIZATION_MSG;
		/* At first send  MQTT charging phase signal to the customer interface */
		if (conn->ctx->last_v2g_msg != V2G_AUTHORIZATION_MSG) {
			// TODO: signal finishing of charging initialization and starting of authorization
		}

		exi_out->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
		init_iso1AuthorizationResType(&exi_out->V2G_Message.Body.AuthorizationRes);
		next_v2g_event = handle_iso_authorization(conn); // [V2G2-562]
	}
	else if (exi_in->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling ChargeParameterDiscoveryReq");
		conn->ctx->current_v2g_msg = V2G_CHARGE_PARAMETER_DISCOVERY_MSG;
		/* At first send  MQTT charging phase signal to the customer interface */
		if ((conn->ctx->last_v2g_msg != V2G_CHARGE_PARAMETER_DISCOVERY_MSG) && (conn->ctx->last_v2g_msg != V2G_POWER_DELIVERY_MSG)) {
			// TODO: signal finishing of authorization phase and starting of parameter-phase
		}
		else if ((conn->ctx->last_v2g_msg == V2G_POWER_DELIVERY_MSG)) { // For the renegotiation process
			// TODO: signal finishing of authorization phase and starting of parameter-phase
		}

		exi_out->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
		init_iso1ChargeParameterDiscoveryResType(&exi_out->V2G_Message.Body.ChargeParameterDiscoveryRes);
		next_v2g_event = handle_iso_charge_parameter_discovery(conn); // [V2G2-565]
	}
	else if (exi_in->V2G_Message.Body.PowerDeliveryReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling PowerDeliveryReq");
		conn->ctx->current_v2g_msg = V2G_POWER_DELIVERY_MSG;
		/* At first send  MQTT charging phase signal to the customer interface */
		if (conn->ctx->is_dc_charger == true) {
			if (conn->ctx->last_v2g_msg == V2G_PRE_CHARGE_MSG) {
				// TODO: signal finishing of precharging phase and starting of charging phase
			}
		}
		else if (conn->ctx->last_v2g_msg == V2G_CHARGE_PARAMETER_DISCOVERY_MSG) {
			// TODO: signal finishing of parameter-phase and starting of charging phase
		}

		exi_out->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
		init_iso1PowerDeliveryResType(&exi_out->V2G_Message.Body.PowerDeliveryRes);
		next_v2g_event = handle_iso_power_delivery(conn); // [V2G2-589]
	}
	else if (exi_in->V2G_Message.Body.ChargingStatusReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling ChargingStatusReq");
		conn->ctx->current_v2g_msg = V2G_CHARGING_STATUS_MSG;

		exi_out->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;
		init_iso1ChargingStatusResType(&exi_out->V2G_Message.Body.ChargingStatusRes);
		next_v2g_event = handle_iso_charging_status(conn);
	}
	else if (exi_in->V2G_Message.Body.MeteringReceiptReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling MeteringReceiptReq");
		conn->ctx->current_v2g_msg = V2G_METERING_RECEIPT_MSG;
		exi_out->V2G_Message.Body.MeteringReceiptRes_isUsed = 1u;
		init_iso1MeteringReceiptResType(&exi_out->V2G_Message.Body.MeteringReceiptRes);
		next_v2g_event = handle_iso_metering_receipt(conn); // [V2G2-796]
	}
	else if (exi_in->V2G_Message.Body.CertificateUpdateReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling CertificateUpdateReq");
		conn->ctx->current_v2g_msg = V2G_CERTIFICATE_UPDATE_MSG;

		exi_out->V2G_Message.Body.CertificateUpdateRes_isUsed = 1u;
		init_iso1CertificateUpdateResType(&exi_out->V2G_Message.Body.CertificateUpdateRes);
		next_v2g_event = handle_iso_certificate_update(conn); // [V2G2-556]
	}
	else if (exi_in->V2G_Message.Body.CertificateInstallationReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling CertificateInstallationReq");
		conn->ctx->current_v2g_msg = V2G_CERTIFICATE_INSTALLATION_MSG;
		dlog(DLOG_LEVEL_INFO, "CertificateInstallation-phase started");

		exi_out->V2G_Message.Body.CertificateInstallationRes_isUsed = 1u;
		init_iso1CertificateInstallationResType(&exi_out->V2G_Message.Body.CertificateInstallationRes);
		next_v2g_event = handle_iso_certificate_installation(conn); // [V2G2-553]
	}
	else if (exi_in->V2G_Message.Body.CableCheckReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling CableCheckReq");
		conn->ctx->current_v2g_msg = V2G_CABLE_CHECK_MSG;
		/* At first send mqtt charging phase signal to the customer interface */
		if (V2G_CHARGE_PARAMETER_DISCOVERY_MSG == conn->ctx->last_v2g_msg) {
			// TODO: signal finishing of parameter-phase and starting of isolation phase
		}

		exi_out->V2G_Message.Body.CableCheckRes_isUsed = 1u;
		init_iso1CableCheckResType(&exi_out->V2G_Message.Body.CableCheckRes);
		next_v2g_event = handle_iso_cable_check(conn); // [V2G2-583
	}
	else if (exi_in->V2G_Message.Body.PreChargeReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling PreChargeReq");
		conn->ctx->current_v2g_msg = V2G_PRE_CHARGE_MSG;
		/* At first send  mqtt charging phase signal to the customer interface */
		if (V2G_CABLE_CHECK_MSG == conn->ctx->last_v2g_msg) {
			// TODO: signal finishing of isolation phase and starting of precharge phase
			dlog(DLOG_LEVEL_INFO, "Precharge-phase started");
		}

		exi_out->V2G_Message.Body.PreChargeRes_isUsed = 1u;
		init_iso1PreChargeResType(&exi_out->V2G_Message.Body.PreChargeRes);
		next_v2g_event = handle_iso_pre_charge(conn); // [V2G2-586]
	}
	else if (exi_in->V2G_Message.Body.WeldingDetectionReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling WeldingDetectionReq");
		conn->ctx->current_v2g_msg = V2G_WELDING_DETECTION_MSG;
		if (V2G_WELDING_DETECTION_MSG != conn->ctx->last_v2g_msg){
			// TODO: signal finishing of charging phase and starting of welding phase
			dlog(DLOG_LEVEL_INFO, "Welding-phase started");
		}
		exi_out->V2G_Message.Body.WeldingDetectionRes_isUsed = 1u;
		init_iso1WeldingDetectionResType(&exi_out->V2G_Message.Body.WeldingDetectionRes);
		next_v2g_event = handle_iso_welding_detection(conn); // [V2G2-596]
	}
	else if (exi_in->V2G_Message.Body.SessionStopReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling SessionStopReq");
		conn->ctx->current_v2g_msg = V2G_SESSION_STOP_MSG;
		/* At first send  mqtt charging phase signal to the customer interface */
		if (V2G_WELDING_DETECTION_MSG == conn->ctx->last_v2g_msg){
			// TODO: signal finishing of welding phase
		}
		else {
			// TODO: signal finishing of charging phase
		}
		exi_out->V2G_Message.Body.SessionStopRes_isUsed = 1u;
		init_iso1SessionStopResType(&exi_out->V2G_Message.Body.SessionStopRes);
		next_v2g_event = handle_iso_session_stop(conn); // [V2G2-570]
	}
	else {
		dlog(DLOG_LEVEL_ERROR, "create_response_message: request type not found");
		next_v2g_event = V2G_EVENT_IGNORE_MSG;
	}
	dlog(DLOG_LEVEL_TRACE, "Current state: %s", conn->ctx->is_dc_charger? iso_dc_states[conn->ctx->state].description : iso_ac_states[conn->ctx->state].description);

	// If next_v2g_event == V2G_EVENT_IGNORE_MSG, keep the current state and ignore msg
	if (next_v2g_event != V2G_EVENT_IGNORE_MSG) {
		conn->ctx->last_v2g_msg = conn->ctx->current_v2g_msg;

		/* Configure session id */
		memcpy(exi_out->V2G_Message.Header.SessionID.bytes, &conn->ctx->resume_data.session_id, iso1MessageHeaderType_SessionID_BYTES_SIZE);

		/* We always set bytesLen to iso1MessageHeaderType_SessionID_BYTES_SIZE */
		exi_out->V2G_Message.Header.SessionID.bytesLen = iso1MessageHeaderType_SessionID_BYTES_SIZE;
	}

	return next_v2g_event;
}
