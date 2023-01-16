// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h> // sleep

#include "v2g_ctx.hpp"
#include "log.hpp"

void init_physical_value(struct iso1PhysicalValueType * const physicalValue, iso1unitSymbolType unit) {
    physicalValue->Multiplier = 0;
    physicalValue->Unit = unit;
    physicalValue->Value = 0;
}

// Only for AC
bool populate_physical_value(struct iso1PhysicalValueType *pv, long long int value, iso1unitSymbolType unit) {
    struct iso1PhysicalValueType physic_tmp = {pv->Multiplier, pv->Unit, pv->Value}; // To restore
    pv->Unit = unit;
    pv->Multiplier = 0; // with integers, we don't need negative multipliers for precision, so start at 0

    // if the value is too large to be represented in 16 signed bits, increase the multiplier
    while ((value > INT16_MAX) || (value < INT16_MIN)) {
        pv->Multiplier++;
        value /= 10;
    }

    if((pv->Multiplier < PHY_VALUE_MULT_MIN) || (pv->Multiplier > PHY_VALUE_MULT_MAX)) {
        memcpy(pv, &physic_tmp, sizeof(struct iso1PhysicalValueType));
        dlog(DLOG_LEVEL_WARNING, "Physical value out of scope. Ignore value");
        return false;
    }

    pv->Value = value;

    return true;
}

void populate_physical_value_float(struct iso1PhysicalValueType *pv, float value, uint8_t decimal_places, iso1unitSymbolType unit) {
    if(false == populate_physical_value(pv, (long long int) value, unit)) {
        return;
    }

    if(0 == pv->Multiplier) {
        for(uint8_t idx = 0; idx < decimal_places; idx++) {
            if(((long int)(value * 10) < INT16_MAX) && ((long int)(value * 10) > INT16_MIN)) {
                pv->Multiplier--;
                value *= 10;
            }
        }
    }

    if (pv->Multiplier != -decimal_places) {
        dlog(DLOG_LEVEL_WARNING, "Possible precision loss while converting to physical value type");
    }

    pv->Value = value;
}

void setMinPhysicalValue(struct iso1PhysicalValueType *ADstPhyValue, const struct iso1PhysicalValueType *ASrcPhyValue, unsigned int * AIsUsed) {

    if(((NULL != AIsUsed) && (0 == *AIsUsed)) || ((pow(10, ASrcPhyValue->Multiplier)  * ASrcPhyValue->Value) < (pow(10, ADstPhyValue->Multiplier) * ADstPhyValue->Value))) {
        ADstPhyValue->Multiplier = ASrcPhyValue->Multiplier;
        ADstPhyValue->Value = ASrcPhyValue->Value;

        if (NULL != AIsUsed) {
            *AIsUsed = 1;
        }
    }
}

static void *v2g_ctx_eventloop(void *data)
{
    struct v2g_context *ctx = (struct v2g_context *)data;

    while (!ctx->shutdown) {
        int rv;

        rv = event_base_loop(ctx->event_base, 0);
        if (rv == -1)
            break;

        /* if no events are registered, restart looping */
        if (rv == 1)
            sleep(1); /* FIXME this is bad since we actually do busy-waiting here */
    }

    return NULL;
}

static int v2g_ctx_start_events(struct v2g_context *ctx)
{
    pthread_attr_t attr;
    int rv;

    /* create the thread in detached state so we don't need to join it later */
    if (pthread_attr_init(&attr) != 0) {
        dlog(DLOG_LEVEL_ERROR, "pthread_attr_init failed: %s", strerror(errno));
        return -1;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        dlog(DLOG_LEVEL_ERROR, "pthread_attr_setdetachstate failed: %s", strerror(errno));
        return -1;
    }

    rv = pthread_create(&ctx->event_thread, NULL, v2g_ctx_eventloop, ctx);
    return rv ? -1 : 0;
}

void v2g_ctx_init_charging_session (struct v2g_context * const ctx, bool is_connection_terminated) {
    v2g_ctx_init_charging_state(ctx, is_connection_terminated); // Init charging state
    v2g_ctx_init_charging_values(ctx); // Loads the internal default config
}

void v2g_ctx_init_charging_state(struct v2g_context * const ctx, bool is_connection_terminated) {
    ctx->stop_hlc = false;
    ctx->intl_emergency_shutdown = false;
    ctx->is_connection_terminated = is_connection_terminated;
    ctx->last_v2g_msg = V2G_UNKNOWN_MSG;
    ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
    ctx->state = 0; // WAIT_FOR_SESSIONSETUP
    ctx->selected_protocol = V2G_UNKNOWN_PROTOCOL;
    ctx->renegotiation_required = false;

    /* Reset timer */
    if (NULL != ctx->com_setup_timeout) {
        event_free(ctx->com_setup_timeout);
        ctx->com_setup_timeout = NULL;
    }
}

void v2g_ctx_init_charging_values(struct v2g_context * const ctx) {
    static bool initialize_once = false;
    const char init_service_name[] = {"EVCharging_Service"};

    ctx->ci_evse.session_id = (uint64_t) 0;  /* store associated session id, this is zero until SessionSetupRes is sent */
    ctx->ci_evse.notification_max_delay = (uint32_t) 0;
    ctx->ci_evse.evse_isolation_status = (uint8_t) iso1isolationLevelType_Invalid;
    ctx->ci_evse.evse_isolation_status_is_used = (unsigned int) 1; // Shall be used in DIN
    ctx->ci_evse.evse_notification = (uint8_t) 0;
    memset(ctx->ci_evse.evse_status_code, iso1DC_EVSEStatusCodeType_EVSE_NotReady, PHASE_LENGTH);
    memset(ctx->ci_evse.evse_processing, iso1EVSEProcessingType_Ongoing, PHASE_LENGTH);
    strcpy((char*) ctx->ci_evse.evse_id.bytes, "DE*CBY*ETE1*234");
    ctx->ci_evse.evse_id.bytesLen = (uint16_t) strlen((const char*) ctx->ci_evse.evse_id.bytes);
    ctx->ci_evse.date_time_now_is_used = (unsigned int) 0;

    ctx->ci_evse.charge_service.FreeService = 0;
    ctx->ci_evse.charge_service.ServiceCategory = iso1serviceCategoryType_EVCharging;
    ctx->ci_evse.charge_service.ServiceID = (uint16_t) 1;
    memcpy(ctx->ci_evse.charge_service.ServiceName.characters, init_service_name, sizeof(init_service_name));
    ctx->ci_evse.charge_service.ServiceName.charactersLen = sizeof(init_service_name);
    ctx->ci_evse.charge_service.ServiceName_isUsed = 0;
    //ctx->ci_evse.chargeService.ServiceScope.characters
    //ctx->ci_evse.chargeService.ServiceScope.charactersLen
    ctx->ci_evse.charge_service.ServiceScope_isUsed = (unsigned int) 0;
    ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0] = iso1EnergyTransferModeType_AC_single_phase_core;
    ctx->ci_evse.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen = 1;

    /* Simple mode does not overwrite the service list after reconnect */
    if(ctx->evse_charging_type != CHARGING_TYPE_HLC_AC || initialize_once == false) {
        ctx->ci_evse.evse_service_list[0].FreeService = (int) 0;
        ctx->ci_evse.evse_service_list[0].ServiceID = 4; // 4 (UseCaseInformation) A list containing information on all other services than charging services. The EVCC and the SECC shall use the ServiceIDs in the range from 1 to 4 as defined in this
        //ctx->ci_evse.evse_service_list[0].ServiceCategory Not needed at the moment, because it is a fixed value in din and iso
        ctx->ci_evse.evse_service_list_len = (uint16_t) 0; // TODO for ISO!!!
        ctx->ci_evse.evse_service_list_write_idx = (uint8_t) 0;
        memset(&ctx->ci_evse.service_parameter_list, 0, sizeof(struct iso1ServiceParameterListType) * iso1ServiceListType_Service_ARRAY_SIZE);
    }

    //SAScheduleTupleID#PMaxScheduleTupleID#Start#Duration#PMax#
    init_physical_value(&ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax, iso1unitSymbolType_W);
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration = (uint32_t) 0;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration_isUsed = (unsigned int) 1;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start = (uint32_t) 0;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval_isUsed = (unsigned int) 1; // Optional: In DIN/ISO it must be set to 1
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].TimeInterval_isUsed = (unsigned int) 0;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.arrayLen = 1;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].SalesTariff_isUsed = (unsigned int) 0;
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].SAScheduleTupleID = (uint8_t) 1; // [V2G2-773]  1 to 255
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.arrayLen = (uint16_t) 1;
    ctx->ci_evse.evse_sa_schedule_list_is_used = false;

    //ctx->ci_evse.evseSAScheduleTuple.SalesTariff
    ctx->ci_evse.evse_sa_schedule_list.SAScheduleTuple.array[0].SalesTariff_isUsed = (unsigned int) 0; // Not supported in DIN

    ctx->ci_evse.payment_option_list[0] =  iso1paymentOptionType_ExternalPayment;
    ctx->ci_evse.payment_option_list[1] =  iso1paymentOptionType_ExternalPayment;
    ctx->ci_evse.payment_option_list_len = (uint8_t) 1; // One option must be set

    if(NULL != ctx->ci_evse.certInstallResB64Buffer) free(ctx->ci_evse.certInstallResB64Buffer);
    ctx->ci_evse.certInstallResB64Buffer = NULL;

    // AC paramter
    ctx->ci_evse.rcd = (int) 0; // 0 if RCD has not detected an error
    ctx->ci_evse.receipt_required = (int) 0;
    ctx->ci_evse.contactor_is_closed = false;

    // evse power values
    init_physical_value(&ctx->ci_evse.evse_current_regulation_tolerance, iso1unitSymbolType_A);
    ctx->ci_evse.evse_current_regulation_tolerance_is_used = (unsigned int) 0; // optional in din
    init_physical_value(&ctx->ci_evse.evse_energy_to_be_delivered, iso1unitSymbolType_Wh);
    ctx->ci_evse.evse_energy_to_be_delivered_is_used = (unsigned int) 0; // optional in din
    init_physical_value(&ctx->ci_evse.evse_maximum_current_limit, iso1unitSymbolType_A);
    ctx->ci_evse.evse_maximum_current_limit_is_used = (unsigned int) 0;
    ctx->ci_evse.evse_current_limit_achieved = (int) 1;
    init_physical_value(&ctx->ci_evse.evse_maximum_power_limit, iso1unitSymbolType_W);
    ctx->ci_evse.evse_maximum_power_limit_is_used = (unsigned int) 0;
    ctx->ci_evse.evse_power_limit_achieved = (int) 1;
    init_physical_value(&ctx->ci_evse.evse_maximum_voltage_limit, iso1unitSymbolType_V);

    ctx->ci_evse.evse_maximum_voltage_limit_is_used = (unsigned int) 0; // mandatory
    ctx->ci_evse.evse_voltage_limit_achieved = (int) 1;
    init_physical_value(&ctx->ci_evse.evse_minimum_current_limit, iso1unitSymbolType_A);
    init_physical_value(&ctx->ci_evse.evse_minimum_voltage_limit, iso1unitSymbolType_V);
    init_physical_value(&ctx->ci_evse.evse_peak_current_ripple, iso1unitSymbolType_A);
    init_physical_value(&ctx->ci_evse.evse_present_voltage, iso1unitSymbolType_V);
    init_physical_value(&ctx->ci_evse.evse_present_current, iso1unitSymbolType_A);
    // AC evse power values
    init_physical_value(&ctx->ci_evse.evse_nominal_voltage, iso1unitSymbolType_V);

    // Init ev received v2g-data to an invalid state
    memset(&ctx->evV2gData.evCurrentDemandReq, 0xff, sizeof(ctx->evV2gData.evCurrentDemandReq));

    /* OppCharge specific configuration */
    if (ctx->evse_charging_type == CHARGING_TYPE_OPPCHARGE) {
        ctx->ci_evse.evse_status_code[PHASE_ISOLATION] = iso1DC_EVSEStatusCodeType_Reserved_8;
        ctx->ci_evse.evse_processing[PHASE_AUTH] = iso1EVSEProcessingType_Finished; // Skip auth-phase
        ctx->ci_evse.evse_processing[PHASE_PARAMETER] = iso1EVSEProcessingType_Finished; // Skip parameter-phase
    }

    /* Init session values */
    ctx->session.iso_selected_payment_option = iso1paymentOptionType_ExternalPayment;
    memset(ctx->session.gen_challenge, 0, sizeof(ctx->session.gen_challenge));

    initialize_once = true;
}

struct v2g_context *v2g_ctx_create()
{
    struct v2g_context *ctx;

    ctx = (v2g_context*) calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->tls_security = TLS_SECURITY_PROHIBIT; // default

    ctx->chargeport = 0;

    /* This evse parameter will be initialized once */
    ctx->basicConfig.evse_ac_current_limit = 0.0f;
    memset(ctx->basicConfig.evse_phase_count, 0, sizeof(ctx->basicConfig.evse_phase_count));
    ctx->basicConfig.gridPowerLimitIsUsed = false;
    memset(ctx->basicConfig.keyFilePw, 0, sizeof(ctx->basicConfig.keyFilePw));

    ctx->certFilePath = NULL;
    ctx->privateKeyFilePath = NULL;

    ctx->local_tcp_addr = NULL;
    ctx->local_tcp_addr = NULL;

    ctx->is_dc_charger = true;

    v2g_ctx_init_charging_session(ctx, true);

    /* interface from config file or options */
    ctx->ifname = "eth1";
    ctx->evse_charging_type = CHARGING_TYPE_HLC;

    ctx->network_read_timeout = 1000;

    ctx->sdp_socket= -1;
    ctx->tcp_socket= -1;
    ctx->tls_socket.fd = -1;
    memset(&ctx->tls_log_ctx, 0, sizeof(keylogDebugCtx));
    ctx->endTlsDebugBySessionStop = true;


    ctx->pncDebugMode = false;

    ctx->mqtt_data.authorization_status = -1;

    /* according to man page, both functions never return an error */
    evthread_use_pthreads();
    pthread_mutex_init(&ctx->mqtt_lock, NULL);
    pthread_condattr_init(&ctx->mqtt_attr);
    pthread_condattr_setclock(&ctx->mqtt_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&ctx->mqtt_cond, &ctx->mqtt_attr);

    ctx->event_base = event_base_new();
    if (!ctx->event_base) {
        dlog(DLOG_LEVEL_ERROR, "event_base_new failed");
        goto free_out;
    }

    if (v2g_ctx_start_events(ctx) != 0)
        goto free_out;

    ctx->com_setup_timeout = NULL;

    return ctx;

free_out:
    if (ctx->event_base) {
        event_base_loopbreak(ctx->event_base);
        event_base_free(ctx->event_base);
    }
    free(ctx->local_tls_addr);
    free(ctx->local_tcp_addr);
    free(ctx);
    return NULL;
}

static void v2g_ctx_free_tls(struct v2g_context *ctx)
{
    mbedtls_net_free(&ctx->tls_socket);

    for(uint8_t idx = 0; idx < ctx->numOfTlsCrt; idx++) {
        mbedtls_pk_free(&ctx->evseTlsCrtKey[idx]);
        mbedtls_x509_crt_free(&ctx->evseTlsCrt[idx]);
    }
    if (ctx->evseTlsCrt != NULL) free(ctx->evseTlsCrt);
    if (ctx->evseTlsCrtKey != NULL)free(ctx->evseTlsCrtKey);

    mbedtls_x509_crt_free(&ctx->v2gRootCrt);
    mbedtls_ssl_config_free(&ctx->ssl_config);

    if (NULL != ctx->tls_log_ctx.file) {
        fclose(ctx->tls_log_ctx.file);
        memset(&ctx->tls_log_ctx, 0, sizeof(ctx->tls_log_ctx));
    }
}

void v2g_ctx_free(struct v2g_context *ctx)
{
    if (ctx->event_base) {
        event_base_loopbreak(ctx->event_base);
        event_base_free(ctx->event_base);
    }

    pthread_cond_destroy(&ctx->mqtt_cond);
    pthread_mutex_destroy(&ctx->mqtt_lock);

    v2g_ctx_free_tls(ctx);

    if(NULL != ctx->privateKeyFilePath) free(ctx->privateKeyFilePath);
    if(NULL != ctx->certFilePath) free(ctx->certFilePath);

    if(ctx->local_tls_addr != NULL)
        free(ctx->local_tls_addr);
    if(ctx->local_tcp_addr != NULL)
        free(ctx->local_tcp_addr);
    if(ctx != NULL)
        free(ctx);
}

void stop_timer(struct event ** event_timer, char const * const timer_name, struct v2g_context *ctx) {
	pthread_mutex_lock(&ctx->mqtt_lock);
	if (NULL != *event_timer) {
		event_free(*event_timer);
		*event_timer = NULL; // Reset timer pointer
		if (NULL != timer_name) {
			dlog(DLOG_LEVEL_TRACE, "%s stopped", (timer_name == NULL)? "Timer" : timer_name);
		}
	}
	pthread_mutex_unlock(&ctx->mqtt_lock);
}
