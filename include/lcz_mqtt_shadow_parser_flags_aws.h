/**
 * @file lcz_mqtt_shadow_parser_flags_aws.h
 * @brief Flag definitions for AWS
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#ifndef __LCZ_MQTT_SHADOW_PARSER_FLAGS_H__
#define __LCZ_MQTT_SHADOW_PARSER_FLAGS_H__

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr.h>

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
/* strstr results of topic string */
struct topic_flags {
	bool get_accepted : 1;
	bool gateway : 1;
};

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_MQTT_SHADOW_PARSER_FLAGS_H__ */
