// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <openv2g/iso1EXIDatatypes.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <openv2g/EXITypes.h>
#include <openv2g/iso1EXIDatatypes.h>
#include <openv2g/iso1EXIDatatypesEncoder.h>
#include <openv2g/xmldsigEXIDatatypes.h>
#include <openv2g/xmldsigEXIDatatypesEncoder.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>

#include "iso_server.hpp"
#include "log.hpp"
#include "v2g_server.hpp"
#include "v2g_ctx.hpp"
#include "tools.hpp"

#define MAX_EXI_SIZE 8192
#define DIGEST_SIZE 32

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

/*!
 * \brief convertIso1ToXmldsigSignedInfoType This function copies V2G iso1SignedInfoType struct into xmldsigSignedInfoType struct type
 * \param xmld_sig_signed_info is the destination struct
 * \param iso1_signed_info is the source struct
 */
static void convertIso1ToXmldsigSignedInfoType(struct xmldsigSignedInfoType* xmld_sig_signed_info,
                                               const struct iso1SignedInfoType* iso1_signed_info) {
    init_xmldsigSignedInfoType(xmld_sig_signed_info);

    for(uint8_t idx = 0; idx < iso1_signed_info->Reference.arrayLen; idx++) {
        const struct iso1ReferenceType *iso1_ref = &iso1_signed_info->Reference.array[idx];
        struct xmldsigReferenceType *xmld_sig_ref = &xmld_sig_signed_info->Reference.array[idx];

        xmld_sig_ref->DigestMethod.Algorithm.charactersLen = iso1_ref->DigestMethod.Algorithm.charactersLen;
        memcpy(xmld_sig_ref->DigestMethod.Algorithm.characters, iso1_ref->DigestMethod.Algorithm.characters,
               iso1_ref->DigestMethod.Algorithm.charactersLen);
        // TODO: Not all elements are copied yet
        xmld_sig_ref->DigestMethod.ANY_isUsed = 0;
        xmld_sig_ref->DigestValue.bytesLen = iso1_ref->DigestValue.bytesLen;
        memcpy(xmld_sig_ref->DigestValue.bytes, iso1_ref->DigestValue.bytes,  iso1_ref->DigestValue.bytesLen);

        xmld_sig_ref->Id_isUsed = iso1_ref->Id_isUsed;
        if (0 != iso1_ref->Id_isUsed) memcpy(xmld_sig_ref->Id.characters, iso1_ref->Id.characters, iso1_ref->Id.charactersLen);
        xmld_sig_ref->Id.charactersLen = iso1_ref->Id.charactersLen;
        xmld_sig_ref->Transforms_isUsed = iso1_ref->Transforms_isUsed;

        xmld_sig_ref->Transforms.Transform.arrayLen = iso1_ref->Transforms.Transform.arrayLen;
        xmld_sig_ref->Transforms.Transform.array[0].Algorithm.charactersLen =
                iso1_ref->Transforms.Transform.array[0].Algorithm.charactersLen;
        memcpy(xmld_sig_ref->Transforms.Transform.array[0].Algorithm.characters,
                iso1_ref->Transforms.Transform.array[0].Algorithm.characters,
                iso1_ref->Transforms.Transform.array[0].Algorithm.charactersLen);
        xmld_sig_ref->Transforms.Transform.array[0].XPath.arrayLen = iso1_ref->Transforms.Transform.array[0].XPath.arrayLen;
        xmld_sig_ref->Transforms.Transform.array[0].ANY_isUsed = 0;
        xmld_sig_ref->Type_isUsed = iso1_ref->Type_isUsed;
        xmld_sig_ref->URI_isUsed = iso1_ref->URI_isUsed;
        xmld_sig_ref->URI.charactersLen = iso1_ref->URI.charactersLen;
        if (0 != iso1_ref->URI_isUsed) memcpy(xmld_sig_ref->URI.characters, iso1_ref->URI.characters, iso1_ref->URI.charactersLen);
    }

    xmld_sig_signed_info->Reference.arrayLen = iso1_signed_info->Reference.arrayLen;
    xmld_sig_signed_info->CanonicalizationMethod.ANY_isUsed = 0;
    xmld_sig_signed_info->Id_isUsed = iso1_signed_info->Id_isUsed;
    if (0 != iso1_signed_info->Id_isUsed) memcpy(xmld_sig_signed_info->Id.characters, iso1_signed_info->Id.characters, iso1_signed_info->Id.charactersLen);
    xmld_sig_signed_info->Id.charactersLen = iso1_signed_info->Id.charactersLen;
    memcpy(xmld_sig_signed_info->CanonicalizationMethod.Algorithm.characters,
           iso1_signed_info->CanonicalizationMethod.Algorithm.characters,
           iso1_signed_info->CanonicalizationMethod.Algorithm.charactersLen);
    xmld_sig_signed_info->CanonicalizationMethod.Algorithm.charactersLen =
            iso1_signed_info->CanonicalizationMethod.Algorithm.charactersLen;

    xmld_sig_signed_info->SignatureMethod.HMACOutputLength_isUsed = iso1_signed_info->SignatureMethod.HMACOutputLength_isUsed;
    xmld_sig_signed_info->SignatureMethod.Algorithm.charactersLen = iso1_signed_info->SignatureMethod.Algorithm.charactersLen;
    memcpy(xmld_sig_signed_info->SignatureMethod.Algorithm.characters, iso1_signed_info->SignatureMethod.Algorithm.characters,
           iso1_signed_info->SignatureMethod.Algorithm.charactersLen);
    xmld_sig_signed_info->SignatureMethod.ANY_isUsed = 0;
}

/*!
 * \brief check_iso1_signature This function validates the ISO signature
 * \param iso1_signature is the signature of the ISO EXI fragment
 * \param public_key is the public key to validate the signature against the ISO EXI fragment
 * \param iso1_exi_fragment iso1_exi_fragment is the ISO EXI fragment
 */
static bool check_iso1_signature(const struct iso1SignatureType* iso1_signature, mbedtls_ecdsa_context* public_key, struct iso1EXIFragment* iso1_exi_fragment) {
    /** Digest check **/
    int err = 0;
    const struct iso1SignatureType* sig = iso1_signature;
    unsigned char buf[MAX_EXI_SIZE];
    size_t buffer_pos = 0;
    const struct iso1ReferenceType *req_ref = &sig->SignedInfo.Reference.array[0];
    bitstream_t stream = { MAX_EXI_SIZE, buf, &buffer_pos, 0, 8 /* Set to 8 for send and 0 for recv */};
    uint8_t digest[DIGEST_SIZE];
    err = encode_iso1ExiFragment(&stream, iso1_exi_fragment);
    if (err != 0) {
        dlog(DLOG_LEVEL_ERROR, "unable to encode fragment, error code = %d", err);
        return false;
    }
    mbedtls_sha256(buf, buffer_pos, digest, 0);

    if (req_ref->DigestValue.bytesLen != DIGEST_SIZE) {
        dlog(DLOG_LEVEL_ERROR, "invalid digest length %u in signature", req_ref->DigestValue.bytesLen);
        return false;
    }

    if (memcmp(req_ref->DigestValue.bytes, digest, DIGEST_SIZE) != 0) {
        dlog(DLOG_LEVEL_ERROR, "invalid digest in signature");
        return false;
    }

    /** Validate signature **/
    struct xmldsigEXIFragment sig_fragment;
    init_xmldsigEXIFragment(&sig_fragment);
    sig_fragment.SignedInfo_isUsed = 1;
    convertIso1ToXmldsigSignedInfoType(&sig_fragment.SignedInfo, &sig->SignedInfo);

    buffer_pos = 0;
    err = encode_xmldsigExiFragment(&stream, &sig_fragment);

    if (err != 0) {
        dlog(DLOG_LEVEL_ERROR, "unable to encode XML signature fragment, error code = %d", err);
        return false;
    }

    /* Hash the signature */
    mbedtls_sha256(buf, buffer_pos, digest, 0);

    /* Validate the ecdsa signature using the public key */
    if (0 == sig->SignatureValue.CONTENT.bytesLen) {
        dlog(DLOG_LEVEL_ERROR, "signature len is invalid (%i)", sig->SignatureValue.CONTENT.bytesLen);
        return false;
    }

    /* Init mbedtls parameter */
    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_group_init(&ecp_group);

    mbedtls_mpi mpi_r;
    mbedtls_mpi_init(&mpi_r);
    mbedtls_mpi mpi_s;
    mbedtls_mpi_init(&mpi_s);

    mbedtls_mpi_read_binary(&mpi_r, (const unsigned char *) &sig->SignatureValue.CONTENT.bytes[0], sig->SignatureValue.CONTENT.bytesLen/2);
    mbedtls_mpi_read_binary(&mpi_s, (const unsigned char *) &sig->SignatureValue.CONTENT.bytes[sig->SignatureValue.CONTENT.bytesLen/2], sig->SignatureValue.CONTENT.bytesLen/2);

	err = mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_SECP256R1);
	
    if (err  == 0) {
        err = mbedtls_ecdsa_verify(&ecp_group, (const unsigned char *) digest, 32, &public_key->Q, &mpi_r, &mpi_s);
    }

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_mpi_free(&mpi_r);
    mbedtls_mpi_free(&mpi_s);

    if (err != 0) {
        char error_buf[100];
        mbedtls_strerror(err, error_buf, sizeof(error_buf));
        dlog(DLOG_LEVEL_ERROR, "invalid signature, error code = -0x%08x, %s", err, error_buf);
        return false;
    }

    return true;
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

/*!
 * \brief publish_iso_authorization_req This function publishes the publish_iso_authorization_req message to the MQTT interface.
 * \param v2g_authorization_req is the request message.
 */
static void publish_iso_authorization_req(struct iso1AuthorizationReqType const * const v2g_authorization_req) {
    //TODO: V2G values that can be published: Id, Id_isUsed, GenChallenge, GenChallenge_isUsed
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
    struct iso1AuthorizationReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.AuthorizationReq;
    struct iso1AuthorizationResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.AuthorizationRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received ev request message to the customer mqtt interface */
    publish_iso_authorization_req(req);

    res->ResponseCode = iso1responseCodeType_OK;

    if (conn->ctx->last_v2g_msg != V2G_AUTHORIZATION_MSG) { /* [V2G2-684] */
        if (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract) {
            if (req->GenChallenge_isUsed == 0 || req->GenChallenge.bytesLen != 16 // [V2G2-697]  The GenChallenge field shall be exactly 128 bits long.
                || memcmp(req->GenChallenge.bytes, conn->ctx->session.gen_challenge, 16) != 0) {
                dlog(DLOG_LEVEL_ERROR, "Challenge invalid or not present");
                res->ResponseCode = iso1responseCodeType_FAILED_ChallengeInvalid; // [V2G2-475]
                goto error_out;
            }
            if (conn->exi_in.iso1EXIDocument->V2G_Message.Header.Signature_isUsed == 0) {
                dlog(DLOG_LEVEL_ERROR, "Missing signature (Signature_isUsed == 0)");
                res->ResponseCode = iso1responseCodeType_FAILED_SignatureError;
                goto error_out;
            }

            /* Validation of the received signature */
            struct iso1EXIFragment iso1_fragment;
            init_iso1EXIFragment(&iso1_fragment);

            iso1_fragment.AuthorizationReq_isUsed = 1u;
            memcpy(&iso1_fragment.AuthorizationReq, req, sizeof(*req));

            if (check_iso1_signature(&conn->exi_in.iso1EXIDocument->V2G_Message.Header.Signature, 
                &conn->ctx->session.contract.pubkey, &iso1_fragment) == false) {
                res->ResponseCode = iso1responseCodeType_FAILED_SignatureError;
                goto error_out;
            }
        }

        /* Configure EVSE-Processing to 'Finish' if PnC-offline mode is running, otherwise wait for MQTT signal */
        if ((conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract) && 
            (conn->ctx->pncOnlineMode == false)) {
            dlog(DLOG_LEVEL_INFO, "Verification of the authorization req signature was successful!");
            res->EVSEProcessing = iso1EVSEProcessingType_Finished;
        }
        else {
            res->EVSEProcessing = (iso1EVSEProcessingType) conn->ctx->ci_evse.evse_processing[PHASE_AUTH];
        }
    }
    else {
        // ExternalPayment
        res->EVSEProcessing = (iso1EVSEProcessingType) conn->ctx->ci_evse.evse_processing[PHASE_AUTH];
    }

error_out:
    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (iso1EVSEProcessingType_Finished == res->EVSEProcessing) ? 
        (int) iso_dc_state_id::WAIT_FOR_CHARGEPARAMETERDISCOVERY : (int) iso_dc_state_id::WAIT_FOR_AUTHORIZATION; // [V2G-573] (AC) , [V2G-687] (DC)

    return next_event;
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
