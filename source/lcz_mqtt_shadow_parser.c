/**
 * @file lcz_mqtt_shadow_parser.c
 * @brief
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_mqtt_shadow_parser, CONFIG_LCZ_MQTT_SHADOW_PARSER_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#define JSMN_PARENT_LINKS
#define JSMN_HEADER
#include "jsmn.h"
#include "jsmn_json.h"

#include "lcz_mqtt_shadow_parser.h"

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static sys_slist_t lcz_mqtt_shadow_parser_list;

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_mqtt_shadow_parser(const char *topic, const char *json)
{
	sys_snode_t *node;
	struct lcz_mqtt_shadow_parser_agent *agent;
	struct topic_flags *flags;

	/* All modules with jsmn header files have access to the tokenization. */
	jsmn_start(json);
	if (!jsmn_valid()) {
		LOG_ERR("Unable to parse subscription %d", jsmn_tokens_found());
		return;
	}

	flags = lcz_mqtt_shadow_parser_find_flags(topic);

	SYS_SLIST_FOR_EACH_NODE (&lcz_mqtt_shadow_parser_list, node) {
		agent = CONTAINER_OF(node, struct lcz_mqtt_shadow_parser_agent, node);
		if (agent->parser != NULL) {
			jsmn_reset_index();
			agent->parser(topic, flags, json, agent->context);
		}
	}

	jsmn_end();
}

void lcz_mqtt_shadow_parser_register_agent(struct lcz_mqtt_shadow_parser_agent *agent)
{
	sys_slist_append(&lcz_mqtt_shadow_parser_list, &agent->node);
}

int lcz_mqtt_shadow_parser_find_state(void)
{
	jsmn_reset_index();

	return jsmn_find_type("state", JSMN_OBJECT, NO_PARENT);
}

bool lcz_mqtt_shadow_parser_find_uint(uint32_t *value, const char *key)
{
	jsmn_reset_index();

	int location = jsmn_find_type(key, JSMN_PRIMITIVE, NO_PARENT);
	if (location > 0) {
		*value = jsmn_convert_uint(location);
		return true;
	} else {
		*value = 0;
		LOG_DBG("%s not found", key);
		return false;
	}
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
__weak struct topic_flags *lcz_mqtt_shadow_parser_find_flags(const char *topic)
{
	return NULL;
}
