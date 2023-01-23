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
#include <math.h>

#include "iso_server.hpp"
#include "log.hpp"
#include "v2g_server.hpp"
#include "v2g_ctx.hpp"
#include "tools.hpp"

#define MAX_EXI_SIZE 8192
#define DIGEST_SIZE 32

static const char* selected_energy_transfer_mode_string[] = {
	"AC_single_phase_core",
	"AC_three_phase_core",
	"DC_core",
	"DC_extended",
	"DC_combo_core",
	"DC_unique",
};

/*!
 * \brief log_selected_energy_transfer_type This function prints the selected energy transfer mode.
 * \param selected_energy_transfer_mode is the selected energy transfer mode
 */
void log_selected_energy_transfer_type(int selected_energy_transfer_mode) {
	if (selected_energy_transfer_mode >= iso1EnergyTransferModeType_AC_single_phase_core &&
		selected_energy_transfer_mode <= iso1EnergyTransferModeType_DC_unique) {
		dlog(DLOG_LEVEL_INFO, "Selected energy transfer mode: %s", selected_energy_transfer_mode_string[selected_energy_transfer_mode]);
	}
	else {
		dlog(DLOG_LEVEL_WARNING, "Selected energy transfer mode %d is invalid", 
			 selected_energy_transfer_mode);
	}
}

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

/*!
 * \brief populate_ac_evse_status This function configures the evse_status struct
 * \param ctx is the V2G context
 * \param evse_status is the destination struct
 */
static void populate_ac_evse_status(struct v2g_context *ctx, struct iso1AC_EVSEStatusType *evse_status) {
	evse_status->EVSENotification = (iso1EVSENotificationType) ctx->ci_evse.evse_notification;
	evse_status->NotificationMaxDelay = ctx->ci_evse.notification_max_delay;
	evse_status->RCD = ctx->ci_evse.rcd;
}

/*!
 * \brief check_iso1_charging_profile_values This function checks if EV charging profile values are within permissible ranges
 * \param req is the PowerDeliveryReq
 * \param res is the PowerDeliveryRes
 * \param conn holds the structure with the V2G msg pair
 * \param sa_schedule_tuple_idx is the index of SA schedule tuple
 */
static void check_iso1_charging_profile_values(iso1PowerDeliveryReqType *req, iso1PowerDeliveryResType *res, v2g_connection *conn, uint8_t sa_schedule_tuple_idx) {
    if (req->ChargingProfile_isUsed == (unsigned int) 1) {

        const struct iso1PMaxScheduleType * evse_p_max_schedule = &conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[sa_schedule_tuple_idx].PMaxSchedule;

        uint32_t ev_time_sum = 0; // Summed EV relative time interval
        uint32_t evse_time_sum = 0; // Summed EVSE relative time interval
        uint8_t evse_idx = 0; // Actual PMaxScheduleEntry index
        bool ev_time_is_within_profile_entry = false; // Is true if the summed EV relative time interval is within the actual EVSE time interval */

        /* Check if the EV ChargingProfileEntryStart time and PMax value fits with the provided EVSE PMaxScheduleEntry list. [V2G2-293] */
        for (uint8_t ev_idx = 0; ev_idx < req->ChargingProfile.ProfileEntry.arrayLen && (res->ResponseCode == iso1responseCodeType_OK); ev_idx++) {

            ev_time_sum += req->ChargingProfile.ProfileEntry.array[ev_idx].ChargingProfileEntryStart;

            while (evse_idx < evse_p_max_schedule->PMaxScheduleEntry.arrayLen && (ev_time_is_within_profile_entry == false)) {

                /* Check if EV ChargingProfileEntryStart value is within one EVSE schedule entry.
                 * The last element must be checked separately, because of the duration value */

                /* If we found an entry which fits in the EVSE time schedule, check if the next EV time slot fits as well
                 * Otherwise check if the next time interval fits in the EVSE time schedule */
                evse_time_sum += evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx].RelativeTimeInterval.start;

                /* Check the time intervals, in the last schedule element the duration value must be considered */
                if (evse_idx < (evse_p_max_schedule->PMaxScheduleEntry.arrayLen - 1)) {
                    ev_time_is_within_profile_entry = (ev_time_sum >= evse_time_sum) &&
                                                      (ev_time_sum < (evse_time_sum + evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx+1].RelativeTimeInterval.start));
                }
                else {
                    ev_time_is_within_profile_entry = (ev_time_sum >= evse_time_sum) &&
                                                      (ev_time_sum <= (evse_time_sum + evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx].RelativeTimeInterval.duration_isUsed *
                                                                       evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx].RelativeTimeInterval.duration));
                }

                if (ev_time_is_within_profile_entry == true) {
                    /* Check if ev ChargingProfileEntryMaxPower element is equal to or smaller than the limits in respective elements of the PMaxScheduleType */
                    if((req->ChargingProfile.ProfileEntry.array[ev_idx].ChargingProfileEntryMaxPower.Value *
                        pow(10, req->ChargingProfile.ProfileEntry.array[ev_idx].ChargingProfileEntryMaxPower.Multiplier)) >
                            (evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx].PMax.Value * pow(10, evse_p_max_schedule->PMaxScheduleEntry.array[evse_idx].PMax.Multiplier))) {
                        //res->ResponseCode = iso1responseCodeType_FAILED_ChargingProfileInvalid; // [V2G2-224] [V2G2-225] [V2G2-478]
                        // setting response code is commented because some EVs do not support schedules correctly
                        dlog(DLOG_LEVEL_WARNING, "EV's charging profile is invalid (ChargingProfileEntryMaxPower too high)!");
                        break;
                    }
                }
                /* If the last EVSE element is reached and ChargingProfileEntryStart time doesn't fit */
                else if (evse_idx == (evse_p_max_schedule->PMaxScheduleEntry.arrayLen - 1)) {
                    //res->ResponseCode = iso1responseCodeType_FAILED_ChargingProfileInvalid; // EV charing profile time exceeds EVSE provided schedule
                    // setting response code is commented because some EVs do not support schedules correctly
                    dlog(DLOG_LEVEL_WARNING, "EV's charging profile is invalid (EV charging profile time exceeds provided schedule)!");
                }
                else {
                    /* Now we checked if the current EV interval fits within the EVSE interval, but it fails.
                     * Next step is to check the EVSE interval until we reached the last EVSE interval */
                    evse_idx = (ev_time_is_within_profile_entry == false) ? (evse_idx + 1) : evse_idx;
                }
            }
        }
    }
}

static void publish_DC_EVStatusType(struct v2g_context *ctx, const struct iso1DC_EVStatusType& iso1_ev_status) {
    if ((ctx->ev_v2g_data.iso1_dc_ev_status.EVErrorCode != iso1_ev_status.EVErrorCode) ||
            (ctx->ev_v2g_data.iso1_dc_ev_status.EVReady != iso1_ev_status.EVReady) ||
            (ctx->ev_v2g_data.iso1_dc_ev_status.EVRESSSOC != iso1_ev_status.EVRESSSOC)) {
        ctx->ev_v2g_data.iso1_dc_ev_status.EVErrorCode = iso1_ev_status.EVErrorCode;
        ctx->ev_v2g_data.iso1_dc_ev_status.EVReady = iso1_ev_status.EVReady;
        ctx->ev_v2g_data.iso1_dc_ev_status.EVRESSSOC = iso1_ev_status.EVRESSSOC;

        types::iso15118_charger::DC_EVStatusType ev_status;
        ev_status.DC_EVErrorCode = static_cast<types::iso15118_charger::DC_EVErrorCode>(iso1_ev_status.EVErrorCode);
        ev_status.DC_EVReady = iso1_ev_status.EVReady;
        ev_status.DC_EVRESSSOC = static_cast<float>(iso1_ev_status.EVRESSSOC);
        ctx->p_charger->publish_DC_EVStatus(ev_status);
    }
}

static void publish_DC_EVTargetVoltageCurrent(struct v2g_context *ctx,
        const struct iso1PhysicalValueType &iso1_dc_ev_target_voltage, const struct iso1PhysicalValueType &iso1_dc_ev_target_current) {
    types::iso15118_charger::DC_EVTargetValues DC_EVTargetValues;
    DC_EVTargetValues.DC_EVTargetVoltage = calc_physical_value(iso1_dc_ev_target_voltage.Value, iso1_dc_ev_target_voltage.Multiplier);
    DC_EVTargetValues.DC_EVTargetCurrent = calc_physical_value(iso1_dc_ev_target_current.Value, iso1_dc_ev_target_current.Multiplier);
    double old_target_voltage = calc_physical_value(ctx->ev_v2g_data.iso1_ev_target_voltage.Value, ctx->ev_v2g_data.iso1_ev_target_voltage.Multiplier);
    double old_target_current = calc_physical_value(ctx->ev_v2g_data.iso1_ev_target_current.Value, ctx->ev_v2g_data.iso1_ev_target_current.Multiplier);

    if ((old_target_voltage != DC_EVTargetValues.DC_EVTargetVoltage) || (old_target_current != DC_EVTargetValues.DC_EVTargetCurrent)) {
        memcpy(&ctx->ev_v2g_data.iso1_ev_target_voltage, &iso1_dc_ev_target_voltage, sizeof(iso1PhysicalValueType));
        memcpy(&ctx->ev_v2g_data.iso1_ev_target_current, &iso1_dc_ev_target_current, sizeof(iso1PhysicalValueType));
        ctx->p_charger->publish_DC_EVTargetVoltageCurrent(DC_EVTargetValues);
    }
}

static void publish_DC_EVMaximumLimits(struct v2g_context *ctx,
        const struct iso1PhysicalValueType &iso1_dc_ev_max_current_limit, const unsigned int &iso1_dc_ev_max_current_limit_is_used,
        const struct iso1PhysicalValueType &iso1_dc_ev_max_power_limit, const unsigned int &iso1_dc_ev_max_power_limit_is_used,
        const struct iso1PhysicalValueType &iso1_dc_ev_max_voltage_limit, const unsigned int &iso1_dc_ev_max_voltage_limit_is_used) {
    types::iso15118_charger::DC_EVMaximumLimits DC_EVMaximumLimits;
    double old_max_current_limit = calc_physical_value(ctx->ev_v2g_data.iso1_ev_maximum_current_limit.Value, ctx->ev_v2g_data.iso1_ev_maximum_current_limit.Multiplier);
    double old_max_power_limit = calc_physical_value(ctx->ev_v2g_data.iso1_ev_maximum_power_limit.Value, ctx->ev_v2g_data.iso1_ev_maximum_power_limit.Multiplier);
    double old_max_voltage_limit = calc_physical_value(ctx->ev_v2g_data.iso1_ev_maximum_voltage_limit.Value, ctx->ev_v2g_data.iso1_ev_maximum_voltage_limit.Multiplier);
    bool publish_message = false;

    if (iso1_dc_ev_max_current_limit_is_used == (unsigned int) 1) {
        DC_EVMaximumLimits.DC_EVMaximumCurrentLimit = calc_physical_value(iso1_dc_ev_max_current_limit.Value, iso1_dc_ev_max_current_limit.Multiplier);
        if (old_max_current_limit != DC_EVMaximumLimits.DC_EVMaximumCurrentLimit.value()) {
            memcpy(&ctx->ev_v2g_data.iso1_ev_maximum_current_limit, &iso1_dc_ev_max_current_limit, sizeof(iso1PhysicalValueType));
            publish_message = true;
        }
    }
    if (iso1_dc_ev_max_power_limit_is_used == (unsigned int) 1) {
        DC_EVMaximumLimits.DC_EVMaximumPowerLimit = calc_physical_value(iso1_dc_ev_max_power_limit.Value, iso1_dc_ev_max_power_limit.Multiplier);
        if (old_max_power_limit != DC_EVMaximumLimits.DC_EVMaximumPowerLimit.value()) {
            memcpy(&ctx->ev_v2g_data.iso1_ev_maximum_power_limit, &iso1_dc_ev_max_power_limit, sizeof(iso1PhysicalValueType));
            publish_message = true;
        }
    }
    if (iso1_dc_ev_max_voltage_limit_is_used == (unsigned int) 1) {
        DC_EVMaximumLimits.DC_EVMaximumVoltageLimit = calc_physical_value(iso1_dc_ev_max_voltage_limit.Value, iso1_dc_ev_max_voltage_limit.Multiplier);
        if (old_max_voltage_limit != DC_EVMaximumLimits.DC_EVMaximumVoltageLimit.value()) {
            memcpy(&ctx->ev_v2g_data.iso1_ev_maximum_voltage_limit, &iso1_dc_ev_max_voltage_limit, sizeof(iso1PhysicalValueType));
            publish_message = true;
        }
    }

    if (publish_message == true) {
        ctx->p_charger->publish_DC_EVMaximumLimits(DC_EVMaximumLimits);
    }
}

static void publish_DC_EVRemainingTime(struct v2g_context *ctx,
        const struct iso1PhysicalValueType &iso1_dc_ev_remaining_time_to_full_soc, const unsigned int &iso1_dc_ev_remaining_time_to_full_soc_is_used,
        const struct iso1PhysicalValueType &iso1_dc_ev_remaining_time_to_bulk_soc, const unsigned int &iso1_dc_ev_remaining_time_to_bulk_soc_is_used) {
    types::iso15118_charger::DC_EVRemainingTime DC_EVRemainingTime;
    const char *format = "%Y-%m-%dT%H:%M:%SZ";
    char buffer[100];
    std::time_t time_now_in_sec = time (NULL);
    double old_remaining_time_to_full_soc = calc_physical_value(ctx->ev_v2g_data.iso1_remaining_time_to_full_soc.Value, ctx->ev_v2g_data.iso1_remaining_time_to_full_soc.Multiplier);
    double old_remaining_time_to_bulk_soc = calc_physical_value(ctx->ev_v2g_data.iso1_remaining_time_to_bulk_soc.Value, ctx->ev_v2g_data.iso1_remaining_time_to_bulk_soc.Multiplier);
    bool publish_message = false;

    if (iso1_dc_ev_remaining_time_to_full_soc_is_used == (unsigned int) 1) {
        double remaining_time_to_full_soc = calc_physical_value(iso1_dc_ev_remaining_time_to_full_soc.Value, iso1_dc_ev_remaining_time_to_full_soc.Multiplier);
        if (old_remaining_time_to_full_soc != remaining_time_to_full_soc) {
            time_now_in_sec += remaining_time_to_full_soc;
            std::strftime(buffer, sizeof(buffer), format, std::gmtime(&time_now_in_sec));
            DC_EVRemainingTime.EV_RemainingTimeToFullSoC = static_cast<boost::optional<std::string>>(buffer);
            memcpy(&ctx->ev_v2g_data.iso1_remaining_time_to_full_soc, &iso1_dc_ev_remaining_time_to_full_soc, sizeof(iso1PhysicalValueType));
            publish_message = true;
        }
    }
    if (iso1_dc_ev_remaining_time_to_bulk_soc_is_used == (unsigned int) 1) {
        double remaining_time_to_bulk_soc = calc_physical_value(iso1_dc_ev_remaining_time_to_bulk_soc.Value, iso1_dc_ev_remaining_time_to_bulk_soc.Multiplier);
        if (old_remaining_time_to_bulk_soc != remaining_time_to_bulk_soc) {
            time_now_in_sec += remaining_time_to_bulk_soc;
            std::strftime(buffer, sizeof(buffer), format, std::gmtime(&time_now_in_sec));
            DC_EVRemainingTime.EV_RemainingTimeToBulkSoC = static_cast<boost::optional<std::string>>(buffer);
            memcpy(&ctx->ev_v2g_data.iso1_remaining_time_to_bulk_soc, &iso1_dc_ev_remaining_time_to_bulk_soc, sizeof(iso1PhysicalValueType));
            publish_message = true;
        }
    }

    if (publish_message == true) {
        ctx->p_charger->publish_DC_EVRemainingTime(DC_EVRemainingTime);
    }
}
//=============================================
//             Publishing request msg
//=============================================

/*!
 * \brief publish_iso_service_discovery_req This function publishes the iso_service_discovery_req message to the MQTT interface.
 * \param iso1ServiceDiscoveryReqType is the request message.
 * \param chargeport is the topic prefix port value.
 */
static void publish_iso_service_discovery_req(struct iso1ServiceDiscoveryReqType const * const v2g_service_discovery_req, int chargeport) {
	//TODO: V2G values that can be published: ServiceCategory, ServiceScope
}

/*!
 * \brief publish_iso_service_detail_req This function publishes the iso_service_detail_req message to the MQTT interface.
 * \param v2g_service_detail_req is the request message.
 * \param chargeport is the topic prefix port value.
 */
static void publish_iso_service_detail_req(struct iso1ServiceDetailReqType const * const v2g_service_detail_req, int chargeport) {
	//TODO: V2G values that can be published: ServiceID
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

/*!
 * \brief publish_iso_charge_parameter_discovery_req This function publishes the charge_parameter_discovery_req message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_charge_parameter_discovery_req is the request message.
 */
static void publish_iso_charge_parameter_discovery_req(struct v2g_context *ctx, struct iso1ChargeParameterDiscoveryReqType const * const v2g_charge_parameter_discovery_req) {
    //TODO: V2G values that can be published: DC_EVChargeParameter, MaxEntriesSAScheduleTuple
    ctx->p_charger->publish_RequestedEnergyTransferMode(static_cast<types::iso15118_charger::EnergyTransferMode>(v2g_charge_parameter_discovery_req->RequestedEnergyTransferMode));
    if(v2g_charge_parameter_discovery_req->AC_EVChargeParameter_isUsed == (unsigned int) 1) {
        if (v2g_charge_parameter_discovery_req->AC_EVChargeParameter.DepartureTime_isUsed == (unsigned int) 1) {
            ctx->p_charger->publish_DepartureTime(std::to_string(v2g_charge_parameter_discovery_req->AC_EVChargeParameter.DepartureTime));
        }
            ctx->p_charger->publish_AC_EAmount(calc_physical_value(v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EAmount.Value,
                                                              v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EAmount.Multiplier));
            ctx->p_charger->publish_AC_EVMaxVoltage(calc_physical_value(v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMaxVoltage.Value,
                                               v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMaxVoltage.Multiplier));
            ctx->p_charger->publish_AC_EVMaxCurrent(calc_physical_value(v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMaxCurrent.Value,
                                               v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMaxCurrent.Multiplier));
            ctx->p_charger->publish_AC_EVMinCurrent(calc_physical_value(v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMinCurrent.Value,
                                               v2g_charge_parameter_discovery_req->AC_EVChargeParameter.EVMinCurrent.Multiplier));
    }
    else if(v2g_charge_parameter_discovery_req->DC_EVChargeParameter_isUsed == (unsigned int) 1) {
        if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.DepartureTime_isUsed == (unsigned int) 1) {
            ctx->p_charger->publish_DepartureTime(std::to_string(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.DepartureTime));

            if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity_isUsed == (unsigned int) 1) {
                ctx->p_charger->publish_DC_EVEnergyCapacity(calc_physical_value(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity.Value,
                                                       v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity.Multiplier));
            }
            if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest_isUsed == (unsigned int) 1) {
                ctx->p_charger->publish_DC_EVEnergyRequest(calc_physical_value(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest.Value,
                                                      v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest.Multiplier));
            }
            if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.FullSOC_isUsed == (unsigned int) 1) {
                ctx->p_charger->publish_DC_FullSOC(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.FullSOC);
            }
            if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.BulkSOC_isUsed == (unsigned int) 1) {
                ctx->p_charger->publish_DC_BulkSOC(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.BulkSOC);
            }
            publish_DC_EVMaximumLimits(ctx,
                    v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumCurrentLimit, (unsigned int) 1,
                    v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumPowerLimit, v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumPowerLimit_isUsed,
                    v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumVoltageLimit, (unsigned int) 1);
            publish_DC_EVStatusType(ctx, v2g_charge_parameter_discovery_req->DC_EVChargeParameter.DC_EVStatus);
        }
    }
}

/*!
 * \brief publish_iso_pre_charge_req This function publishes the iso_pre_charge_req message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_precharge_req is the request message.
 */
static void publish_iso_pre_charge_req(struct v2g_context *ctx, struct iso1PreChargeReqType const * const v2g_precharge_req) {
    publish_DC_EVTargetVoltageCurrent(ctx, v2g_precharge_req->EVTargetVoltage, v2g_precharge_req->EVTargetCurrent);
    publish_DC_EVStatusType(ctx, v2g_precharge_req->DC_EVStatus);
}

/*!
 * \brief publish_iso_power_delivery_req This function publishes the iso_power_delivery_req message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_power_delivery_req is the request message.
 */
static void publish_iso_power_delivery_req(struct v2g_context *ctx, struct iso1PowerDeliveryReqType const * const v2g_power_delivery_req) {
    //TODO: V2G values that can be published: ChargeProgress, SAScheduleTupleID
    if (v2g_power_delivery_req->DC_EVPowerDeliveryParameter_isUsed == (unsigned int) 1) {
        ctx->p_charger->publish_DC_ChargingComplete(v2g_power_delivery_req->DC_EVPowerDeliveryParameter.ChargingComplete);
        if(v2g_power_delivery_req->DC_EVPowerDeliveryParameter.BulkChargingComplete_isUsed == (unsigned int) 1) {
            ctx->p_charger->publish_DC_BulkChargingComplete(v2g_power_delivery_req->DC_EVPowerDeliveryParameter.BulkChargingComplete);
        }
        publish_DC_EVStatusType(ctx, v2g_power_delivery_req->DC_EVPowerDeliveryParameter.DC_EVStatus);
    }

}

/*!
 * \brief publish_iso_current_demand_req This function publishes the iso_current_demand_req message to the MQTT interface.
 * \param ctx is the V2G context
 * \param v2g_current_demand_req is the request message.
 */
static void publish_iso_current_demand_req(struct v2g_context *ctx, struct iso1CurrentDemandReqType const * const v2g_current_demand_req) {
    if ((v2g_current_demand_req->BulkChargingComplete_isUsed == (unsigned int) 1) &&
            (ctx->ev_v2g_data.bulk_charging_complete != v2g_current_demand_req->BulkChargingComplete)) {
        ctx->p_charger->publish_DC_BulkChargingComplete(v2g_current_demand_req->BulkChargingComplete);
        ctx->ev_v2g_data.bulk_charging_complete = v2g_current_demand_req->BulkChargingComplete;
    }
    if (ctx->ev_v2g_data.charging_complete != v2g_current_demand_req->ChargingComplete) {
        ctx->p_charger->publish_DC_ChargingComplete(v2g_current_demand_req->ChargingComplete);
        ctx->ev_v2g_data.charging_complete = v2g_current_demand_req->ChargingComplete;
    }

    publish_DC_EVStatusType(ctx, v2g_current_demand_req->DC_EVStatus);

    publish_DC_EVTargetVoltageCurrent(ctx, v2g_current_demand_req->EVTargetVoltage, v2g_current_demand_req->EVTargetCurrent);

    publish_DC_EVMaximumLimits(ctx,
            v2g_current_demand_req->EVMaximumCurrentLimit, v2g_current_demand_req->EVMaximumCurrentLimit_isUsed,
            v2g_current_demand_req->EVMaximumPowerLimit, v2g_current_demand_req->EVMaximumPowerLimit_isUsed,
            v2g_current_demand_req->EVMaximumVoltageLimit, v2g_current_demand_req->EVMaximumVoltageLimit_isUsed);

    publish_DC_EVRemainingTime(ctx,
            v2g_current_demand_req->RemainingTimeToFullSoC, v2g_current_demand_req->RemainingTimeToFullSoC_isUsed,
            v2g_current_demand_req->RemainingTimeToBulkSoC, v2g_current_demand_req->RemainingTimeToBulkSoC_isUsed);
}
/*!
 * \brief publish_iso_metering_receipt_req This function publishes the iso_metering_receipt_req message to the MQTT interface.
 * \param v2g_metering_receipt_req is the request message.
 */
static void publish_iso_metering_receipt_req(struct iso1MeteringReceiptReqType const * const v2g_metering_receipt_req) {
    // TODO: publish PnC only
}

/*!
 * \brief publish_iso_welding_detection_req This function publishes the iso_welding_detection_req message to the MQTT interface.
 * \param p_charger to publish MQTT topics.
 * \param v2g_welding_detection_req is the request message.
 */
static void publish_iso_welding_detection_req(struct v2g_context *ctx, struct iso1WeldingDetectionReqType const * const v2g_welding_detection_req) {
    //TODO: V2G values that can be published: EVErrorCode, EVReady, EVRESSSOC
    publish_DC_EVStatusType(ctx, v2g_welding_detection_req->DC_EVStatus);
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

	/* format EVCC ID */
	for (i = 0; i < req->EVCCID.bytesLen; i++) {
		sprintf(&buffer[i * 3], "%02" PRIx8 ":", req->EVCCID.bytes[i]);
	}
	if (i)
		buffer[i * 3 - 1] = '\0';
	else
		buffer[0] = '\0';

    conn->ctx->p_charger->publish_EVCCIDD(buffer); // publish EVCC ID

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
        (false == conn->ctx->debugMode)) {
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
	struct iso1ServiceDetailReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.ServiceDetailReq;
	struct iso1ServiceDetailResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.ServiceDetailRes;
	enum v2g_event next_event = V2G_EVENT_NO_EVENT;

	/* At first, publish the received ev request message to the MQTT interface */
	publish_iso_service_detail_req(req, conn->ctx->chargeport);

	res->ResponseCode = iso1responseCodeType_OK;

	/* ServiceID reported back always matches the requested one */
	res->ServiceID = req->ServiceID;

	bool service_id_found = false;

	for(uint8_t idx = 0; idx < conn->ctx->ci_evse.evse_service_list_len; idx++) {

		if (req->ServiceID == conn->ctx->ci_evse.evse_service_list[idx].ServiceID) {
			service_id_found = true;

			/* Fill parameter list of the requested service id [V2G2-549] */
			for (uint8_t idx2 = 0; idx2 < conn->ctx->ci_evse.service_parameter_list[idx].ParameterSet.arrayLen; idx2++) {
				res->ServiceParameterList.ParameterSet.array[idx2] = conn->ctx->ci_evse.service_parameter_list[idx].ParameterSet.array[idx2];
			}
			res->ServiceParameterList.ParameterSet.arrayLen = conn->ctx->ci_evse.service_parameter_list[idx].ParameterSet.arrayLen;
			res->ServiceParameterList_isUsed = (res->ServiceParameterList.ParameterSet.arrayLen != 0)? 1 : 0;
		}
	}
	service_id_found = (req->ServiceID == V2G_SERVICE_ID_CHARGING)? true : service_id_found;

	if (false == service_id_found) {
		res->ResponseCode = iso1responseCodeType_FAILED_ServiceIDInvalid; // [V2G2-464]
	}

	/* Check the current response code and check if no external error has occurred */
	next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

	/* Set next expected req msg */
	conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_SVCDETAIL_PAYMENTSVCSEL; // [V2G-DC-548]

	return next_event;
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
            conn->ctx->p_charger->publish_SelectedPaymentOption(static_cast<types::iso15118_charger::PaymentOption>(req->SelectedPaymentOption));
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
    struct iso1ChargeParameterDiscoveryReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct iso1ChargeParameterDiscoveryResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.ChargeParameterDiscoveryRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;
    struct timespec ts_abs_timeout;

    /* At first, publish the received ev request message to the MQTT interface */
    publish_iso_charge_parameter_discovery_req(conn->ctx, req);

    /* First, check requested energy transfer mode, because this information is necessary for futher configuration */
    res->ResponseCode = iso1responseCodeType_FAILED_WrongEnergyTransferMode;
    for(uint8_t idx = 0; idx < conn->ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen; idx++) {
        if(req->RequestedEnergyTransferMode == conn->ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[idx]) {
            res->ResponseCode = iso1responseCodeType_OK; // [V2G2-476]
            log_selected_energy_transfer_type((int) req->RequestedEnergyTransferMode);
            break;
        }
    }

    res->EVSEChargeParameter_isUsed = 0;
    res->EVSEProcessing = (iso1EVSEProcessingType) conn->ctx->ci_evse.evse_processing[PHASE_PARAMETER];

    /* Configure SA-schedules*/
    if (res->EVSEProcessing == iso1EVSEProcessingType_Finished) {
        /* If processing is finished, configure SASchedule list */
        if (conn->ctx->ci_evse.evse_sa_schedule_list_is_used == false) {
            /* If not configured, configure SA-schedule automatically */
            if (conn->ctx->evse_charging_type == CHARGING_TYPE_HLC_AC) {
                /* Determin max current and nominal voltage */
                float max_current = conn->ctx->basicConfig.evse_ac_current_limit;
                int64_t nom_voltage = conn->ctx->ci_evse.evse_nominal_voltage.Value * pow(10, conn->ctx->ci_evse.evse_nominal_voltage.Multiplier); /* nominal voltage */

                /* Calculate pmax based on max current, nominal voltage and phase count (which the car has selected above) */
                int64_t pmax = max_current * nom_voltage * ((req->RequestedEnergyTransferMode == iso1EnergyTransferModeType_AC_single_phase_core) ? 1 : 3);
                populate_physical_value(&conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax,
                                        pmax, iso1unitSymbolType_W);                
            }
            else {
                conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax = conn->ctx->ci_evse.evse_maximum_power_limit;
            }
            conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start = 0;
            conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration_isUsed = 1;
            conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration = SA_SCHEDULE_DURATION;
            conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.arrayLen = 1;
            conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.arrayLen = 1;
        }

        res->SAScheduleList = conn->ctx->ci_evse.evse_sa_schedule_list;
        res->SAScheduleList_isUsed = (unsigned int) 1; //  The SECC shall only omit the parameter 'SAScheduleList' in case EVSEProcessing is set to 'Ongoing'.

        if((req->MaxEntriesSAScheduleTuple_isUsed == (unsigned int) 1) && (req->MaxEntriesSAScheduleTuple < res->SAScheduleList.SAScheduleTuple.arrayLen)) {
            dlog(DLOG_LEVEL_WARNING, "EV's max. SA-schedule-tuple entries exceeded");
        }
    }
    else {
        res->EVSEProcessing = iso1EVSEProcessingType_Ongoing;
        res->SAScheduleList_isUsed = (unsigned int) 0;
    }

    /* Checking SAScheduleTupleID */
    for(uint8_t idx = 0; idx < res->SAScheduleList.SAScheduleTuple.arrayLen; idx++) {
        if (res->SAScheduleList.SAScheduleTuple.array[idx].SAScheduleTupleID == (uint8_t) 0) {
            dlog(DLOG_LEVEL_WARNING, "Selected SAScheduleTupleID is not ISO15118 conform. The SECC shall use the values 1 to 255"); // [V2G2-773]  The SECC shall use the values 1 to 255 for the parameter SAScheduleTupleID.
        }
    }

    res->SASchedules_isUsed = 0;

	// TODO: For DC charging wait for CP state B , before transmitting of the response ([V2G2-921], [V2G2-922]). CP state is checked by other module

    /* reset our internal reminder that renegotiation was requested */
    conn->ctx->session.renegotiation_required = false; // Reset renegotiation flag

    if (conn->ctx->is_dc_charger == false) {
        /* Configure AC stucture elements */
        res->AC_EVSEChargeParameter_isUsed = 1;
        res->DC_EVSEChargeParameter_isUsed = 0;

        populate_ac_evse_status(conn->ctx, &res->AC_EVSEChargeParameter.AC_EVSEStatus);

        /* Max current */
        float max_current = conn->ctx->basicConfig.evse_ac_current_limit;
        populate_physical_value_float(&res->AC_EVSEChargeParameter.EVSEMaxCurrent, max_current, 1, iso1unitSymbolType_A);

        /* Nominal voltage */
        res->AC_EVSEChargeParameter.EVSENominalVoltage = conn->ctx->ci_evse.evse_nominal_voltage;
        int64_t nom_voltage = conn->ctx->ci_evse.evse_nominal_voltage.Value * pow(10, conn->ctx->ci_evse.evse_nominal_voltage.Multiplier);

        /* Calculate pmax based on max current, nominal voltage and phase count (which the car has selected above) */
        int64_t pmax = max_current * nom_voltage * ((iso1EnergyTransferModeType_AC_single_phase_core == req->RequestedEnergyTransferMode)? 1 : 3);

        /* Check the SASchedule */
        if (res->SAScheduleList_isUsed == (unsigned int) 1) {
            for(uint8_t idx = 0; idx < res->SAScheduleList.SAScheduleTuple.arrayLen; idx++) {
                for(uint8_t idx2 = 0; idx2 < res->SAScheduleList.SAScheduleTuple.array[idx].PMaxSchedule.PMaxScheduleEntry.arrayLen; idx2++)
                    if((res->SAScheduleList.SAScheduleTuple.array[idx].PMaxSchedule.PMaxScheduleEntry.array[idx2].PMax.Value * pow(10, res->SAScheduleList.SAScheduleTuple.array[idx].PMaxSchedule.PMaxScheduleEntry.array[idx2].PMax.Multiplier)) > pmax) {
                        dlog(DLOG_LEVEL_WARNING, "Provided SA-schedule-list doesn't match with the physical value limits");
                    }
            }
        }

        if(req->DC_EVChargeParameter_isUsed == (unsigned int) 1) {
            res->ResponseCode = iso1responseCodeType_FAILED_WrongChargeParameter; // [V2G2-477]
        }
    }
    else {
        /* Configure DC stucture elements */
        res->DC_EVSEChargeParameter_isUsed = 1;
        res->AC_EVSEChargeParameter_isUsed = 0;

        res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
        res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
        res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSENotification  = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
        res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_PARAMETER];
        res->DC_EVSEChargeParameter.DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;

        res->DC_EVSEChargeParameter.EVSECurrentRegulationTolerance = conn->ctx->ci_evse.evse_current_regulation_tolerance;
        res->DC_EVSEChargeParameter.EVSECurrentRegulationTolerance_isUsed = conn->ctx->ci_evse.evse_current_regulation_tolerance_is_used;
        res->DC_EVSEChargeParameter.EVSEEnergyToBeDelivered = conn->ctx->ci_evse.evse_energy_to_be_delivered;
        res->DC_EVSEChargeParameter.EVSEEnergyToBeDelivered_isUsed = conn->ctx->ci_evse.evse_energy_to_be_delivered_is_used;
        res->DC_EVSEChargeParameter.EVSEMaximumCurrentLimit = conn->ctx->ci_evse.evse_maximum_current_limit;
        res->DC_EVSEChargeParameter.EVSEMaximumPowerLimit = conn->ctx->ci_evse.evse_maximum_power_limit;
        res->DC_EVSEChargeParameter.EVSEMaximumVoltageLimit = conn->ctx->ci_evse.evse_maximum_voltage_limit;
        res->DC_EVSEChargeParameter.EVSEMinimumCurrentLimit = conn->ctx->ci_evse.evse_minimum_current_limit;
        res->DC_EVSEChargeParameter.EVSEMinimumVoltageLimit = conn->ctx->ci_evse.evse_minimum_voltage_limit;
        res->DC_EVSEChargeParameter.EVSEPeakCurrentRipple = conn->ctx->ci_evse.evse_peak_current_ripple;

        if((unsigned int) 1 == req->AC_EVChargeParameter_isUsed) {
            res->ResponseCode = iso1responseCodeType_FAILED_WrongChargeParameter; // [V2G2-477]
        }
    }

    /* Stop with failed response code in case fake HLC DC is configured */
    if (conn->ctx->evse_charging_type == CHARGING_TYPE_FAKE_HLC) {
        dlog(DLOG_LEVEL_INFO, "Configure failed response to stop fake hlc DC session");
        res->ResponseCode = iso1responseCodeType_FAILED;
    }

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    if (conn->ctx->is_dc_charger == true) {
        conn->ctx->state = (iso1EVSEProcessingType_Finished == res->EVSEProcessing) ? (int) iso_dc_state_id::WAIT_FOR_CABLECHECK : (int) iso_dc_state_id::WAIT_FOR_CHARGEPARAMETERDISCOVERY; // [V2G-582], [V2G-688]
    }
    else {
        conn->ctx->state = (iso1EVSEProcessingType_Finished == res->EVSEProcessing) ? (int) iso_ac_state_id::WAIT_FOR_POWERDELIVERY : (int) iso_ac_state_id::WAIT_FOR_CHARGEPARAMETERDISCOVERY;
    }

    return next_event;
}

/*!
 * \brief handle_iso_power_delivery This function handles the iso_power_delivery msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_power_delivery(struct v2g_connection *conn) {
    struct iso1PowerDeliveryReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.PowerDeliveryReq;
    struct iso1PowerDeliveryResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.PowerDeliveryRes;
    struct timespec ts_abs_timeout;
    uint8_t sa_schedule_tuple_idx = 0;
    bool entry_found = false;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_iso_power_delivery_req(conn->ctx, req);

    /* build up response */
    res->ResponseCode = iso1responseCodeType_OK;

    switch (req->ChargeProgress) {
        case iso1chargeProgressType_Start:
            conn->ctx->p_charger->publish_V2G_Setup_Finished(boost::blank{});

            if (conn->ctx->is_dc_charger == false) {
                int rv = 0;
                // TODO: For AC charging wait for CP state C or D , before transmitting of the response. CP state is checked by other module
                if (conn->ctx->ci_evse.contactor_is_closed == false) {
                    // TODO: Signal closing contactor with MQTT if no timeout while waiting for state C or D
                    conn->ctx->p_charger->publish_AC_Close_Contactor(true);
                    conn->ctx->session.is_charging = true;

                    /* determine timeout for contactor */
                    clock_gettime(CLOCK_MONOTONIC, &ts_abs_timeout);
                    timespec_add_ms(&ts_abs_timeout, V2G_CONTACTOR_CLOSE_TIMEOUT);

                    /* wait for contactor to really close or timeout */
                    dlog(DLOG_LEVEL_INFO, "Waiting for contactor is closed");

                    while ((rv == 0) && (conn->ctx->ci_evse.contactor_is_closed == false) &&
                         (conn->ctx->intl_emergency_shutdown == false) &&
                         (conn->ctx->stop_hlc == false) &&
                         (conn->ctx->is_connection_terminated == false)) {
                        pthread_mutex_lock(&conn->ctx->mqtt_lock);
                        rv = pthread_cond_timedwait(&conn->ctx->mqtt_cond, &conn->ctx->mqtt_lock, &ts_abs_timeout);
                        if (rv == EINTR)
                            rv = 0; /* restart */
                        if (rv == ETIMEDOUT) {
                            dlog(DLOG_LEVEL_ERROR, "timeout while waiting for contactor to close, signaling error");
                            res->ResponseCode = iso1responseCodeType_FAILED_ContactorError;
                        }
                        pthread_mutex_unlock(&conn->ctx->mqtt_lock);
                    }
                }
            }
            break;

        case iso1chargeProgressType_Stop:
            conn->ctx->session.is_charging = false;

            if (conn->ctx->is_dc_charger == false) {
                // TODO: For AC charging wait for CP state change from C/D to B , before transmitting of the response. CP state is checked by other module
                conn->ctx->p_charger->publish_AC_Open_Contactor(true);
            }
            else {
                conn->ctx->p_charger->publish_currentDemand_Finished(boost::blank{});
                conn->ctx->p_charger->publish_DC_Open_Contactor(true);
            }
            break;

        case iso1chargeProgressType_Renegotiate:
            conn->ctx->session.renegotiation_required = true;
            break;

        default:
            dlog(DLOG_LEVEL_ERROR, "Unknown ChargeProgress %d received, signaling error", req->ChargeProgress);
            res->ResponseCode = iso1responseCodeType_FAILED;
    }

    if (conn->ctx->is_dc_charger == false) {
        res->AC_EVSEStatus_isUsed = 1;
        res->DC_EVSEStatus_isUsed = 0;
        populate_ac_evse_status(conn->ctx, &res->AC_EVSEStatus);
    }
    else {
        res->DC_EVSEStatus_isUsed = 1;
        res->AC_EVSEStatus_isUsed = 0;
        res->DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
        res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
        res->DC_EVSEStatus.EVSENotification = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
        res->DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_CHARGE];
        res->DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;

        res->ResponseCode = (req->ChargeProgress == iso1chargeProgressType_Start) && (res->DC_EVSEStatus.EVSEStatusCode != iso1DC_EVSEStatusCodeType_EVSE_Ready)?
                                iso1responseCodeType_FAILED_PowerDeliveryNotApplied : res->ResponseCode; // [V2G2-480]
    }

    res->EVSEStatus_isUsed = 0;

    /* Check the selected SAScheduleTupleID */
    for(sa_schedule_tuple_idx = 0; sa_schedule_tuple_idx < conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.arrayLen; sa_schedule_tuple_idx++) {
        if((conn->ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[sa_schedule_tuple_idx].SAScheduleTupleID == req->SAScheduleTupleID)) {
            entry_found = true;
            conn->ctx->session.sa_schedule_tuple_id = req->SAScheduleTupleID;
            break;
        }
    }

    res->ResponseCode = (entry_found == false)? iso1responseCodeType_FAILED_TariffSelectionInvalid : res->ResponseCode; // [V2G2-479]

    /* Check EV charging profile values [V2G2-478] */
    check_iso1_charging_profile_values(req, res, conn, sa_schedule_tuple_idx);

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    if ((req->ChargeProgress == iso1chargeProgressType_Renegotiate) &&
            ((conn->ctx->last_v2g_msg == V2G_CURRENT_DEMAND_MSG) ||
             (conn->ctx->last_v2g_msg == V2G_CHARGING_STATUS_MSG))) {
        conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_CHARGEPARAMETERDISCOVERY; // [V2G-813]

        if (conn->ctx->evse_charging_type == CHARGING_TYPE_HLC_AC) {
            // Intended for AC only
            conn->ctx->ci_evse.evse_notification = (conn->ctx->ci_evse.evse_notification == iso1EVSENotificationType_ReNegotiation) ?
                    iso1EVSENotificationType_None : conn->ctx->ci_evse.evse_notification;
        }
        else {
            // Reset parameter to start the renegotation process
            conn->ctx->ci_evse.evse_processing[PHASE_PARAMETER] = iso1EVSEProcessingType_Ongoing;
            conn->ctx->ci_evse.evse_processing[PHASE_ISOLATION] = iso1EVSEProcessingType_Ongoing;
            conn->ctx->ci_evse.evse_status_code[PHASE_PARAMETER] = iso1DC_EVSEStatusCodeType_EVSE_NotReady;
            conn->ctx->ci_evse.evse_status_code[PHASE_ISOLATION] = iso1DC_EVSEStatusCodeType_EVSE_Ready;
            conn->ctx->ci_evse.evse_status_code[PHASE_PRECHARGE] = iso1DC_EVSEStatusCodeType_EVSE_Ready;
            conn->ctx->ci_evse.evse_status_code[PHASE_CHARGE] = iso1DC_EVSEStatusCodeType_EVSE_Ready;
            conn->ctx->ci_evse.evse_notification = (iso1EVSENotificationType_ReNegotiation == conn->ctx->ci_evse.evse_notification) ?
                    iso1EVSENotificationType_None : conn->ctx->ci_evse.evse_notification;
            conn->ctx->ci_evse.evse_isolation_status = iso1isolationLevelType_Invalid;
        }
    }
    else if ((req->ChargeProgress == iso1chargeProgressType_Start) && (conn->ctx->last_v2g_msg != V2G_CURRENT_DEMAND_MSG) && (conn->ctx->last_v2g_msg != V2G_CHARGING_STATUS_MSG)) {
        conn->ctx->state = (conn->ctx->is_dc_charger == true) ? (int) iso_dc_state_id::WAIT_FOR_CURRENTDEMAND : (int) iso_ac_state_id::WAIT_FOR_CHARGINGSTATUS; // [V2G-590], [V2G2-576]
    }
    else {
        /* abort charging session if EV is ready to charge after current demand phase */
        if (req->ChargeProgress != iso1chargeProgressType_Stop) {
            res->ResponseCode = iso1responseCodeType_FAILED; // (/*[V2G2-812]*/
        }
        conn->ctx->state = (conn->ctx->is_dc_charger == true) ? (int) iso_dc_state_id::WAIT_FOR_WELDINGDETECTION_SESSIONSTOP : (int) iso_ac_state_id::WAIT_FOR_SESSIONSTOP; // [V2G-601], [V2G2-568]
    }

    return next_event;
}

/*!
 * \brief handle_iso_charging_status This function handles the iso_charging_status msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_charging_status(struct v2g_connection *conn) {
    struct iso1ChargingStatusReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.ChargingStatusReq;
    struct iso1ChargingStatusResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.ChargingStatusRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;
    /* build up response */
    res->ResponseCode = iso1responseCodeType_OK;

    res->ReceiptRequired = conn->ctx->ci_evse.receipt_required;
    res->ReceiptRequired_isUsed = (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract)? 1U : 0U; // Is optional, but verisco tester checks this parameter in PnC

    res->MeterInfo_isUsed = 0; // TODO: Configure MeterInfo

    res->EVSEMaxCurrent_isUsed = (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract)? (unsigned int) 0 : (unsigned int) 1; // This element is not included in the message if any AC PnC Message Set has been selected.

    if ((unsigned int) 1 == res->EVSEMaxCurrent_isUsed) {
        populate_physical_value_float(&res->EVSEMaxCurrent , conn->ctx->basicConfig.evse_ac_current_limit, 1, iso1unitSymbolType_A);
    }

    conn->exi_out.iso1EXIDocument->V2G_Message.Body.ChargingStatusRes_isUsed = 1;

    /* the following field can also be set in error path */
    res->EVSEID.charactersLen = conn->ctx->ci_evse.evse_id.bytesLen;
    memcpy(res->EVSEID.characters, conn->ctx->ci_evse.evse_id.bytes, conn->ctx->ci_evse.evse_id.bytesLen);

    /* in error path the session might not be available */
    res->SAScheduleTupleID = conn->ctx->session.sa_schedule_tuple_id;
    populate_ac_evse_status(conn->ctx, &res->AC_EVSEStatus);

    /* Check the current response code and check if no external error has occurred */
    next_event = (enum v2g_event ) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (((int) 1 == res->ReceiptRequired)) ? (int) iso_ac_state_id::WAIT_FOR_METERINGRECEIPT : 
                                                             (int) iso_ac_state_id::WAIT_FOR_CHARGINGSTATUS_POWERDELIVERY; // [V2G2-577], [V2G2-575]

    return next_event;
}

/*!
 * \brief handle_iso_metering_receipt This function handles the iso_metering_receipt msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_metering_receipt(struct v2g_connection *conn) {
    struct iso1MeteringReceiptReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.MeteringReceiptReq;
    struct iso1MeteringReceiptResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.MeteringReceiptRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received ev request message to the MQTTinterface */
    publish_iso_metering_receipt_req(req);

    dlog(DLOG_LEVEL_TRACE, "EVSE side: meteringReceipt called");
    dlog(DLOG_LEVEL_TRACE, "\tReceived data:");

    dlog(DLOG_LEVEL_TRACE, "\t\t ID=%c%c%c", req->Id.characters[0], req->Id.characters[1], req->Id.characters[2]);
    dlog(DLOG_LEVEL_TRACE, "\t\t SAScheduleTupleID=%d", req->SAScheduleTupleID);
    dlog(DLOG_LEVEL_TRACE, "\t\t SessionID=%d", req->SessionID.bytes[1]);
    dlog(DLOG_LEVEL_TRACE, "\t\t MeterInfo.MeterStatus=%d", req->MeterInfo.MeterStatus);
    dlog(DLOG_LEVEL_TRACE, "\t\t MeterInfo.MeterID=%d", req->MeterInfo.MeterID.characters[0]);
    dlog(DLOG_LEVEL_TRACE, "\t\t MeterInfo.isused.MeterReading=%d", req->MeterInfo.MeterReading_isUsed);
    dlog(DLOG_LEVEL_TRACE, "\t\t MeterReading.Value=%lu", (long unsigned int)req->MeterInfo.MeterReading);
    dlog(DLOG_LEVEL_TRACE, "\t\t MeterInfo.TMeter=%li", (long int)req->MeterInfo.TMeter);

    res->ResponseCode = iso1responseCodeType_OK;


    if (conn->ctx->is_dc_charger == false) {
        /* for AC charging we respond with AC_EVSEStatus */
        res->EVSEStatus_isUsed = 0;
        res->AC_EVSEStatus_isUsed = 1;
        res->DC_EVSEStatus_isUsed = 0;
        populate_ac_evse_status(conn->ctx, &res->AC_EVSEStatus);
    }
    else {
        res->DC_EVSEStatus_isUsed = 1;
        res->AC_EVSEStatus_isUsed = 0;
    }

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (conn->ctx->is_dc_charger == false)? (int) iso_ac_state_id::WAIT_FOR_CHARGINGSTATUS_POWERDELIVERY : (int) iso_dc_state_id::WAIT_FOR_CURRENTDEMAND_POWERDELIVERY; // [V2G2-580]/[V2G-797]

    return next_event;
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
    struct iso1CableCheckReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.CableCheckReq;
    struct iso1CableCheckResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.CableCheckRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_DC_EVStatusType(conn->ctx, req->DC_EVStatus);

    // TODO: For DC charging wait for CP state C or D , before transmitting of the response ([V2G2-917], [V2G2-918]). CP state is checked by other module

    /* Fill the CableCheckRes */
    res->ResponseCode = iso1responseCodeType_OK;
    res->DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_ISOLATION];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;
    res->EVSEProcessing = (iso1EVSEProcessingType) conn->ctx->ci_evse.evse_processing[PHASE_ISOLATION];

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (res->EVSEProcessing == iso1EVSEProcessingType_Finished) ? (int) iso_dc_state_id::WAIT_FOR_PRECHARGE : (int) iso_dc_state_id::WAIT_FOR_CABLECHECK; // [V2G-584], [V2G-621]

    return next_event;
}

/*!
 * \brief handle_iso_pre_charge This function handles the iso_pre_charge msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_pre_charge(struct v2g_connection *conn) {
    struct iso1PreChargeReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.PreChargeReq;
    struct iso1PreChargeResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.PreChargeRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_iso_pre_charge_req(conn->ctx, req);

    /* Fill the PreChargeRes*/
    res->DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_PRECHARGE];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;
    res->EVSEPresentVoltage = (iso1PhysicalValueType) conn->ctx->ci_evse.evse_present_voltage;
    res->ResponseCode = iso1responseCodeType_OK;

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_PRECHARGE_POWERDELIVERY; // [V2G-587]

    return next_event;
}

/*!
 * \brief handle_iso_current_demand This function handles the iso_current_demand msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_current_demand(struct v2g_connection *conn) {
    struct iso1CurrentDemandReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.CurrentDemandReq;
    struct iso1CurrentDemandResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.CurrentDemandRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_iso_current_demand_req(conn->ctx, req);

    res->DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_CHARGE];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;
    if ((conn->ctx->ci_evse.evse_maximum_current_limit_is_used == 1) &&
            (calc_physical_value(req->EVTargetCurrent.Value, req->EVTargetCurrent.Multiplier) >=
                    calc_physical_value(conn->ctx->ci_evse.evse_maximum_current_limit.Value, conn->ctx->ci_evse.evse_maximum_current_limit.Multiplier))) {
        conn->ctx->ci_evse.evse_current_limit_achieved = (int) 1;
    }
    else {
        conn->ctx->ci_evse.evse_current_limit_achieved = (int) 0;
    }
    res->EVSECurrentLimitAchieved = conn->ctx->ci_evse.evse_current_limit_achieved;
    memcpy(res->EVSEID.characters, conn->ctx->ci_evse.evse_id.bytes, conn->ctx->ci_evse.evse_id.bytesLen);
    res->EVSEID.charactersLen = conn->ctx->ci_evse.evse_id.bytesLen;
    res->EVSEMaximumCurrentLimit = conn->ctx->ci_evse.evse_maximum_current_limit;
    res->EVSEMaximumCurrentLimit_isUsed = conn->ctx->ci_evse.evse_maximum_current_limit_is_used;
    res->EVSEMaximumPowerLimit = conn->ctx->ci_evse.evse_maximum_power_limit;
    res->EVSEMaximumPowerLimit_isUsed = conn->ctx->ci_evse.evse_maximum_power_limit_is_used;
    res->EVSEMaximumVoltageLimit = conn->ctx->ci_evse.evse_maximum_voltage_limit;
    res->EVSEMaximumVoltageLimit_isUsed = conn->ctx->ci_evse.evse_maximum_voltage_limit_is_used;
    double EVTargetPower = calc_physical_value(req->EVTargetCurrent.Value, req->EVTargetCurrent.Multiplier) *
            calc_physical_value(req->EVTargetVoltage.Value, req->EVTargetVoltage.Multiplier);
    if ((conn->ctx->ci_evse.evse_maximum_power_limit_is_used  == 1) && (EVTargetPower >=
            calc_physical_value(conn->ctx->ci_evse.evse_maximum_power_limit.Value, conn->ctx->ci_evse.evse_maximum_power_limit.Multiplier))) {
        conn->ctx->ci_evse.evse_power_limit_achieved = (int) 1;
    }
    else {
        conn->ctx->ci_evse.evse_power_limit_achieved = (int) 0;
    }
    res->EVSEPowerLimitAchieved = conn->ctx->ci_evse.evse_power_limit_achieved;
    res->EVSEPresentCurrent = conn->ctx->ci_evse.evse_present_current;
    res->EVSEPresentVoltage = conn->ctx->ci_evse.evse_present_voltage;
    if ((conn->ctx->ci_evse.evse_maximum_voltage_limit_is_used  == 1) &&
            (calc_physical_value(req->EVTargetVoltage.Value, req->EVTargetVoltage.Multiplier) >=
                    calc_physical_value(conn->ctx->ci_evse.evse_maximum_voltage_limit.Value, conn->ctx->ci_evse.evse_maximum_voltage_limit.Multiplier))) {
        conn->ctx->ci_evse.evse_voltage_limit_achieved = (int) 1;
    }
    else {
        conn->ctx->ci_evse.evse_voltage_limit_achieved = (int) 0;
    }
    res->EVSEVoltageLimitAchieved = conn->ctx->ci_evse.evse_voltage_limit_achieved;
    //res->MeterInfo // TODO: PNC only
    res->MeterInfo_isUsed = 0;
    res->ReceiptRequired = conn->ctx->ci_evse.receipt_required;// TODO: PNC only
    res->ReceiptRequired_isUsed = (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract)? (unsigned int) conn->ctx->ci_evse.receipt_required : (unsigned int) 0;
    res->ResponseCode = iso1responseCodeType_OK;
    res->SAScheduleTupleID  = conn->ctx->session.sa_schedule_tuple_id;

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = ((res->ReceiptRequired_isUsed == (unsigned int) 1) && (res->ReceiptRequired == (int) 1)) ?
            (int) iso_dc_state_id::WAIT_FOR_METERINGRECEIPT : (int) iso_dc_state_id::WAIT_FOR_CURRENTDEMAND_POWERDELIVERY; // [V2G-795], [V2G-593]

    return next_event;
}

/*!
 * \brief handle_iso_welding_detection This function handles the iso_welding_detection msg pair. It analyzes the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_welding_detection(struct v2g_connection *conn) {
    struct iso1WeldingDetectionReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.WeldingDetectionReq;
    struct iso1WeldingDetectionResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.WeldingDetectionRes;
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_iso_welding_detection_req(conn->ctx, req);

    // TODO: Wait for CP state B, before transmitting of the response, or signal intl_emergency_shutdown in conn->ctx ([V2G2-920], [V2G2-921]).

    res->DC_EVSEStatus.EVSEIsolationStatus = (iso1isolationLevelType) conn->ctx->ci_evse.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->ci_evse.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (iso1EVSENotificationType) conn->ctx->ci_evse.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode = (iso1DC_EVSEStatusCodeType) conn->ctx->ci_evse.evse_status_code[PHASE_WELDING];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint16_t) conn->ctx->ci_evse.notification_max_delay;
    res->EVSEPresentVoltage = conn->ctx->ci_evse.evse_present_voltage;
    res->ResponseCode = iso1responseCodeType_OK;

    /* Check the current response code and check if no external error has occurred */
    next_event = (v2g_event) iso_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_WELDINGDETECTION_SESSIONSTOP; // [V2G-597]

    return next_event;
}

/*!
 * \brief handle_iso_session_stop This function handles the iso_session_stop msg pair. It analyses the request msg and fills the response msg.
 *  The request and response msg based on the open v2g structures. This structures must be provided within the \c conn structure.
 * \param conn holds the structure with the v2g msg pair.
 * \param session_data holds the session data.
 * \return Returns the next v2g-event.
 */
static enum v2g_event handle_iso_session_stop(struct v2g_connection *conn) {
    struct iso1SessionStopReqType *req = &conn->exi_in.iso1EXIDocument->V2G_Message.Body.SessionStopReq;
    struct iso1SessionStopResType *res = &conn->exi_out.iso1EXIDocument->V2G_Message.Body.SessionStopRes;

    res->ResponseCode = iso1responseCodeType_OK;

    /* Check the current response code and check if no external error has occurred */
    iso_validate_response_code(&res->ResponseCode, conn);

     /* Set the next charging state */
    switch (req->ChargingSession) {
        case iso1chargingSessionType_Terminate:
            conn->dlink_action = MQTT_DLINK_ACTION_TERMINATE;
            conn->ctx->p_charger->publish_EV_ChargingSession(static_cast<types::iso15118_charger::ChargingSession>(iso1chargingSessionType_Terminate));
            /* Set next expected req msg */
            conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_TERMINATED_SESSION;
            break;

        case iso1chargingSessionType_Pause:
            /* Set next expected req msg */
            /* Check if the EV is allowed to request the sleep mode. TODO: Remove "true" if sleep mode is supported */
            if (true || ((conn->ctx->last_v2g_msg != V2G_POWER_DELIVERY_MSG) && (conn->ctx->last_v2g_msg != V2G_WELDING_DETECTION_MSG))) {
                conn->dlink_action = MQTT_DLINK_ACTION_TERMINATE;
                conn->ctx->p_charger->publish_EV_ChargingSession(static_cast<types::iso15118_charger::ChargingSession>(iso1chargingSessionType_Terminate));
                res->ResponseCode = iso1responseCodeType_FAILED;
                conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_TERMINATED_SESSION;
            }
            else {
                /* Init sleep mode for the EV */
                conn->dlink_action = MQTT_DLINK_ACTION_PAUSE;
                conn->ctx->p_charger->publish_EV_ChargingSession(static_cast<types::iso15118_charger::ChargingSession>(iso1chargingSessionType_Pause));
                conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_SESSIONSETUP;
            }
            break;

        default:
            /* Set next expected req msg */
            conn->dlink_action = MQTT_DLINK_ACTION_TERMINATE;
            conn->ctx->p_charger->publish_EV_ChargingSession(static_cast<types::iso15118_charger::ChargingSession>(iso1chargingSessionType_Terminate));
            conn->ctx->state = (int) iso_dc_state_id::WAIT_FOR_TERMINATED_SESSION;
    }

    return V2G_EVENT_SEND_AND_TERMINATE; // Charging must be terminated after sending the response message [V2G2-571]
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
        if (conn->ctx->last_v2g_msg == V2G_POWER_DELIVERY_MSG) {
            conn->ctx->p_charger->publish_currentDemand_Started(boost::blank{});
            conn->ctx->session.is_charging = true;
        }
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
        /* At first send  MQTT charging phase signal to the MQTT interface */
        if (conn->ctx->last_v2g_msg != V2G_PAYMENT_DETAILS_MSG) {
            if (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_Contract) {
                conn->ctx->p_charger->publish_Require_Auth_PnC(boost::blank{});
            }
        }
		exi_out->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;
		init_iso1PaymentDetailsResType(&exi_out->V2G_Message.Body.PaymentDetailsRes);
		next_v2g_event = handle_iso_payment_details(conn); // [V2G2-559]
	}
	else if (exi_in->V2G_Message.Body.AuthorizationReq_isUsed) {
		dlog(DLOG_LEVEL_TRACE, "Handling AuthorizationReq");
		conn->ctx->current_v2g_msg = V2G_AUTHORIZATION_MSG;
		/* At first send  MQTT charging phase signal to the MQTT interface */
        if (conn->ctx->last_v2g_msg != V2G_AUTHORIZATION_MSG) {
            if (conn->ctx->session.iso_selected_payment_option == iso1paymentOptionType_ExternalPayment) {
                conn->ctx->p_charger->publish_Require_Auth_EIM(boost::blank{});
            }
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
            conn->ctx->p_charger->publish_Start_CableCheck(boost::blank{});
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
