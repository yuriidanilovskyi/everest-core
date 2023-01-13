// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <openv2g/iso1EXIDatatypes.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "iso_server.hpp"
#include "log.hpp"
#include "v2g_server.hpp"
#include "v2g_ctx.hpp"
#include "tools.hpp"

/*!
 * \brief iso_validate_state This function checks whether the received message is expected and valid at this
 * point in the communication sequence state machine. The current v2g msg type must be set with the current v2g msg state. [V2G2-538]
 * \param state is the current state of the charging session
 * \param current_v2g_msg is the current handled v2g message
 * \param is_dc_charging is \c true if it is a DC charging session
 * \return Returns a iso1responseCode with sequence error if current_v2g_msg is not expected, otherwise OK.
 */
static iso1responseCodeType iso_validate_state(int state, enum V2gMsgTypeId current_v2g_msg, bool is_dc_charging) {

	int allowed_requests = (true == is_dc_charging) ? iso_dc_states[state].allowed_requests : iso_ac_states[state].allowed_requests; // dc_charging is determined in charge_parameter. dc
	return (allowed_requests & (1 << current_v2g_msg)) ? iso1responseCodeType_OK : iso1responseCodeType_FAILED_SequenceError;

}

/*!
 * \brief iso_validate_response_code This function checks if an external error has occurred (sequence error, user abort) ... ).
 * \param iso_response_code is a pointer to the current response code. The value will be modified if an external error has occurred.
 * \param conn the structure with the external error information.
 * \return Returns \c 2 if the charging must be terminated after sending the response message, returns \c 1 if charging must be aborted immediately and
 * 0 if no error
 */
static int iso_validate_response_code(iso1responseCodeType * const v2g_response_code, struct v2g_connection const * const conn) {
	enum v2g_event next_event = V2G_EVENT_NO_EVENT;
	iso1responseCodeType response_code_tmp;

	if (conn->ctx->is_connection_terminated == true) {
		dlog(DLOG_LEVEL_ERROR, "Connection is terminated. Abort charging");
		return V2G_EVENT_TERMINATE_CONNECTION;
	}

	/* If MQTT user abort or emergency shutdown has occurred */
	if((conn->ctx->stop_hlc == true) || (conn->ctx->intl_emergency_shutdown == true)) {
		*v2g_response_code = iso1responseCodeType_FAILED;
	}

	/* [V2G-DC-390]: at this point we must check whether the given request is valid at this step;
	 * the idea is that we catch this error in each function below to respond with a valid
	 * encoded message; note, that the handler functions below must not access v2g_session in
	 * error path, since it might not be set, yet!
	 */
	response_code_tmp = iso_validate_state(conn->ctx->state, conn->ctx->current_v2g_msg, conn->ctx->is_dc_charger); // [V2G2-538]

	*v2g_response_code = (response_code_tmp >= iso1responseCodeType_FAILED)? response_code_tmp : *v2g_response_code;

	/* [V2G2-460]: check whether the session id matches the expected one of the active session */
	*v2g_response_code = ((conn->ctx->current_v2g_msg != V2G_SESSION_SETUP_MSG) && (conn->ctx->resume_data.session_id != conn->ctx->received_session_id))?
							 iso1responseCodeType_FAILED_UnknownSession : *v2g_response_code;

	/* set return value to 1 if the EVSE cannot process this request message */
	if (*v2g_response_code >= iso1responseCodeType_FAILED) {
		next_event = V2G_EVENT_SEND_AND_TERMINATE; // [V2G2-539], [V2G2-034] Send response and terminate tcp-connection

		/* check if the ISO response is within the range of the enum. If not, then the out of range response code will be printed */
		if ((*v2g_response_code >= iso1responseCodeType_OK ) && (*v2g_response_code  <= iso1responseCodeType_FAILED_CertificateRevoked)) {
			dlog(DLOG_LEVEL_ERROR, "Failed response code detected for message \"%s\", error: %s", v2gMsgType[conn->ctx->current_v2g_msg], isoResponse[*v2g_response_code]);
		}
		else {
			dlog(DLOG_LEVEL_ERROR, "Failed response code detected for message \"%s\", Invalid response code: %d", v2gMsgType[conn->ctx->current_v2g_msg], *v2g_response_code);
		}
	}

	return next_event;
}

//=============================================
//             Publishing request msg
//=============================================

/*!
 * \brief publish_iso_session_setup_req This function publishes the iso_session_setup_req message to the MQTT interface.
 * \param v2g_session_setup_req is the request message.
 * \param chargeport is the topic prefix port value.
 */
static void publish_iso_session_setup_req(struct iso1SessionSetupReqType const * const v2g_session_setup_req, int chargeport) {
	uint64_t evccid = 0;
	memcpy(&evccid, v2g_session_setup_req->EVCCID.bytes, min(v2g_session_setup_req->EVCCID.bytesLen, iso1SessionSetupReqType_EVCCID_BYTES_SIZE));
	//TODO: publish evccid to EVCCIDD
}

/*!
 * \brief publish_iso_service_discovery_req This function publishes the iso_service_discovery_req message to the MQTT interface.
 * \param iso1ServiceDiscoveryReqType is the request message.
 * \param chargeport is the topic prefix port value.
 */
static void publish_iso_service_discovery_req(struct iso1ServiceDiscoveryReqType const * const v2g_service_discovery_req, int chargeport) {
	//TODO: V2G values that can be published: ServiceCategory, ServiceScope
}

/*!
 * \brief publish_iso_payment_service_selection_req This function publishes the iso_payment_service_selection_req message to the MQTT interface.
 * \param v2g_payment_service_selection_req is the request message.
 * \param chargeport is the topic prefix port value.
 */
static void publish_iso_payment_service_selection_req(struct iso1PaymentServiceSelectionReqType const * const v2g_payment_service_selection_req) {
    //TODO: V2G values that can be published: SelectedPaymentOption, SelectedServiceList
}

//=============================================
//             Request Handling
//=============================================

/*!
 * \brief handle_iso_session_setup This function handles the iso_session_setup msg pair. It analyzes the request msg and fills the response msg.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_session_setup(struct v2g_connection *conn) {
	struct iso1SessionSetupReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.SessionSetupReq;
	struct iso1SessionSetupResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.SessionSetupRes;
	char buffer[iso1SessionSetupReqType_EVCCID_BYTES_SIZE * 3 - 1 + 1]; /* format: (%02x:) * n - (1x ':') + (1x NULL) */
	int i;
	enum v2g_event next_event = V2G_EVENT_NO_EVENT;

	/* At first, publish the received EV request message to the customer MQTT interface */
	publish_iso_session_setup_req(req, conn->ctx->chargeport);

	/* format EVCC ID */
	for (i = 0; i < req->EVCCID.bytesLen; i++) {
		sprintf(&buffer[i * 3], "%02" PRIx8 ":", req->EVCCID.bytes[i]);
	}
	if (i)
		buffer[i * 3 - 1] = '\0';
	else
		buffer[0] = '\0';

	dlog(DLOG_LEVEL_INFO, "SessionSetupReq.EVCCID: %s", strlen(buffer) ? buffer : "(zero length provided)");

	/* un-arm a potentially communication setup timeout */
	stop_timer(&conn->ctx->com_setup_timeout, "session_setup: V2G_COMMUNICATION_SETUP_TIMER", conn->ctx);

	/* [V2G2-756]: If the SECC receives a SessionSetupReq including a SessionID value which is not
	 * equal to zero (0) and not equal to the SessionID value stored from the preceding V2G
	 * Communication Session, it shall send a SessionID value in the SessionSetupRes message that is
	 * unequal to "0" and unequal to the SessionID value stored from the preceding V2G Communication
	 * Session and indicate the new V2G Communication Session with the ResponseCode set to
	 * "OK_NewSessionEstablished"
	 */

	//TODO: handle resuming sessions [V2G2-463]

	/* Now fill the evse response message */
	res->ResponseCode = iso1responseCodeType_OK_NewSessionEstablished;

	/* Check and init session id */
	/* If no session id is configured, generate one */
	srand((unsigned int) time(NULL));
	if(conn->ctx->ci_evse.session_id == (uint64_t)0) {
		conn->ctx->ci_evse.session_id = ((uint64_t) rand() << 48) | ((uint64_t) rand() << 32) | ((uint64_t) rand() << 16) | (uint64_t) rand();
		dlog(DLOG_LEVEL_INFO, "No session_id found. Generating random session id.");
	}
	conn->ctx->resume_data.session_id = conn->ctx->ci_evse.session_id;
	dlog(DLOG_LEVEL_INFO, "Created new session with id 0x%08" PRIu64, conn->ctx->resume_data.session_id);

	/* TODO: publish EVCCID to MQTT */

	res->EVSEID.charactersLen = conn->ctx->ci_evse.evse_id.bytesLen;
	memcpy(res->EVSEID.characters, conn->ctx->ci_evse.evse_id.bytes, conn->ctx->ci_evse.evse_id.bytesLen);

	res->EVSETimeStamp_isUsed = conn->ctx->ci_evse.date_time_now_is_used;
	res->EVSETimeStamp = time(NULL);

	/* Check the current response code and check if no external error has occurred */
	next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

	/* Set next expected req msg */
	conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_SERVICEDISCOVERY; // [V2G-543]

	return next_event;
}

/*!
 * \brief handle_iso_service_discovery This function handles the din service discovery msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_service_discovery(struct v2g_connection *conn) {
    struct iso1ServiceDiscoveryReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.ServiceDiscoveryReq;
    struct iso1ServiceDiscoveryResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.ServiceDiscoveryRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;
    int8_t scope_idx = -1; // To find a list entry within the evse service list */

    /* At first, publish the received ev request message to the MQTT interface */
    publish_iso_service_discovery_req(req, conn->ctx->chargeport);

    /* build up response */
    res->ResponseCode = iso1responseCodeType_OK;

    // Checking of the charge service id
    if(conn->ctx->ci_evse.charge_service.ServiceID != V2G_SERVICE_ID_CHARGING) {
        dlog(DLOG_LEVEL_WARNING, "Selected ServiceID is not ISO15118 conform. Correcting value to '1' (Charge service id)");
        conn->ctx->ci_evse.charge_service.ServiceID = V2G_SERVICE_ID_CHARGING;
    }
    // Checking of the service category
    if(conn->ctx->ci_evse.charge_service.ServiceCategory != iso1serviceCategoryType_EVCharging) {
        dlog(DLOG_LEVEL_WARNING, "Selected ServiceCategory is not ISO15118 conform. Correcting value to '0' (EVCharging)");
        conn->ctx->ci_evse.charge_service.ServiceCategory = iso1serviceCategoryType_EVCharging;
    }

    res->ChargeService = conn->ctx->ci_evse.charge_service;

    // Checking of the payment options
    if ((!conn->is_tls_connection) && 
        ((conn->ctx->ci_evse.payment_option_list[0] == iso1paymentOptionType_Contract)||
        (conn->ctx->ci_evse.payment_option_list[1] == iso1paymentOptionType_Contract)) && 
        (false == conn->ctx->pncDebugMode)) {
        conn->ctx->ci_evse.payment_option_list[0] = iso1paymentOptionType_ExternalPayment;
        conn->ctx->ci_evse.payment_option_list_len = 1;
        dlog(DLOG_LEVEL_WARNING, "PnC is not allowed without TLS-communication. Correcting value to '1' (ExternalPayment)");
    }

    memcpy(res->PaymentOptionList.PaymentOption.array, conn->ctx->ci_evse.payment_option_list, conn->ctx->ci_evse.payment_option_list_len * sizeof(iso1paymentOptionType));
    res->PaymentOptionList.PaymentOption.arrayLen = conn->ctx->ci_evse.payment_option_list_len;

    /* Find requested scope id within evse service list */
    if (req->ServiceScope_isUsed) {
        /* Check if ServiceScope is in evse ServiceList */
        for(uint8_t idx = 0; idx < res->ServiceList.Service.arrayLen; idx++) {
            if((res->ServiceList.Service.array[idx].ServiceScope_isUsed == (unsigned int) 1) && 
            (strcmp(res->ServiceList.Service.array[idx].ServiceScope.characters, req->ServiceScope.characters) == 0)) {
                scope_idx = idx;
                break;
            }
        }
    }

    /*  The SECC always returns all supported services for all scopes if no specific ServiceScope has been
    	indicated in request message. */
    if(scope_idx == (int8_t) -1) {
        memcpy(res->ServiceList.Service.array, conn->ctx->ci_evse.evse_service_list, sizeof(struct iso1ServiceType) * conn->ctx->ci_evse.evse_service_list_len);
        res->ServiceList.Service.arrayLen = conn->ctx->ci_evse.evse_service_list_len;
    }
    else {
        /* Offer only the requested ServiceScope entry */
        res->ServiceList.Service.array[0] = conn->ctx->ci_evse.evse_service_list[scope_idx];
        res->ServiceList.Service.arrayLen = 1;
    }

    res->ServiceList_isUsed = ((uint16_t) 0 < conn->ctx->ci_evse.evse_service_list_len) ? (unsigned int) 1 : (unsigned int) 0;

    /* Check the current response code and check if no external error has occurred */
    nextEvent = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_SVCDETAIL_PAYMENTSVCSEL; // [V2G-545]

    return nextEvent;
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
    struct iso1PaymentServiceSelectionReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.PaymentServiceSelectionReq;
    struct iso1PaymentServiceSelectionResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.PaymentServiceSelectionRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;
    uint8_t idx = 0;
    bool list_element_found = false;

    /* At first, publish the received ev request message to the customer mqtt interface */
    publish_iso_payment_service_selection_req(req);

    res->ResponseCode = iso1responseCodeType_OK;

    /* check whether the selected payment option was announced at all;
     * this also covers the case that the peer sends any invalid/unknown payment option
     * in the message; if we are not happy -> bail out
     */
    for(idx = 0; idx < conn->ctx->ci_evse.payment_option_list_len; idx++) {
        if((conn->ctx->ci_evse.payment_option_list[idx] == req->SelectedPaymentOption)) {
            list_element_found = true;
            break;
        }
    }
    res->ResponseCode = (list_element_found == true)? res->ResponseCode : iso1responseCodeType_FAILED_PaymentSelectionInvalid; // [V2G2-465]

    /* Check the selected services */
    bool charge_service_found = false;
    bool selected_services_found = true;

    for (uint8_t req_idx = 0; (req_idx < req->SelectedServiceList.SelectedService.arrayLen) && (selected_services_found == true); req_idx++) {

        /* Check if it's a charging service */
        if(req->SelectedServiceList.SelectedService.array[req_idx].ServiceID == V2G_SERVICE_ID_CHARGING) {
            charge_service_found = true;
        }
        /* Otherwise check if the selected service is in the stored in the service list */
        else {
            bool entry_found = false;
            for (uint8_t ci_idx = 0; (ci_idx < conn->ctx->ci_evse.evse_service_list_len) && (entry_found == false); ci_idx++) {

                if (req->SelectedServiceList.SelectedService.array[req_idx].ServiceID == conn->ctx->ci_evse.evse_service_list[ci_idx].ServiceID) {
                    /* If it's stored, search for the next requested SelectedService entry */
                    dlog(DLOG_LEVEL_INFO,"Selected service id %i found", conn->ctx->ci_evse.evse_service_list[ci_idx].ServiceID);
                    entry_found = true;
                    break;
                }
            }
            if (entry_found == false) {
                /* If the requested SelectedService entry was not found, break up service list check */
                selected_services_found = false;
                break;
            }
        }
    }

    res->ResponseCode = (selected_services_found == false)? iso1responseCodeType_FAILED_ServiceSelectionInvalid : res->ResponseCode; // [V2G2-467]
    res->ResponseCode = (charge_service_found == false)? iso1responseCodeType_FAILED_NoChargeServiceSelected : res->ResponseCode; // [V2G2-804]

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    if (req->SelectedPaymentOption == iso1paymentOptionType_Contract) {
        dlog(DLOG_LEVEL_INFO, "SelectedPaymentOption: Contract");
        /* Set next expected req msg */
        conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_PAYMENTDETAILS_CERTINST_CERTUPD; // [V2G-551] (iso specification describes only the ac case... )
    }
    else {
        dlog(DLOG_LEVEL_INFO, "SelectedPaymentOption: ExternalPayment");
        /* Set next expected req msg */
        conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_AUTHORIZATION; // [V2G-551] (iso specification describes only the ac case... )
    }

    return next_event;
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
