/**
 * @file lcz_mqtt_shell.c
 * @brief
 *
 * Copyright (c) 2023 Laird Connectivity LLC
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lcz_mqtt_shell, CONFIG_LCZ_MQTT_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr/init.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/base64.h>
#include <attr.h>

#include "lcz_mqtt.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define ERR_MSG "Error: %d"

struct mqtt_shell_context {
	struct lcz_mqtt_user agent;
	bool credentials_loaded;
	bool connected;
};

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct mqtt_shell_context mqtt_ctx;
static const struct shell *shell_cur;
static uint8_t data_buffer[CONFIG_LCZ_MQTT_SHELL_BUFFER_SIZE];

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int cmd_mqtt_connect(const struct shell *shell, size_t argc, char **argv);
static int cmd_mqtt_disconnect(const struct shell *shell, size_t argc, char **argv);
static int cmd_mqtt_send(const struct shell *shell, size_t argc, char **argv);
static void mqtt_ack_callback(int status);
static void mqtt_connect_callback(int status);
static void mqtt_disconnect_callback(int status);
static int mqtt_shell_init(const struct device *device);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static int cmd_mqtt_connect(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	shell_cur = shell;
	if (mqtt_ctx.connected) {
		ret = -EALREADY;
		goto err;
	}
	if (!mqtt_ctx.credentials_loaded) {
		ret = lcz_mqtt_load_credentials();
		if (ret == 0) {
			mqtt_ctx.credentials_loaded = true;
		} else {
			mqtt_ctx.credentials_loaded = false;
			goto err;
		}
	}
	ret = lcz_mqtt_get_server_addr();
	if (ret != 0) {
		goto err;
	}
	ret = lcz_mqtt_connect();
err:
	if (ret != 0) {
		shell_error(shell, ERR_MSG, ret);
	}
	return ret;
}

static int cmd_mqtt_disconnect(const struct shell *shell, size_t argc, char **argv)
{
	shell_cur = shell;
	return lcz_mqtt_disconnect();
}

static int cmd_mqtt_send(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	size_t decode_len;
	const char *topic;

	shell_cur = shell;

	topic = attr_get_quasi_static(ATTR_ID_mqtt_shell_topic);
	if (!topic || strlen(topic) <= 0) {
		ret = -EINVAL;
		goto err;
	}

	ret = base64_decode(data_buffer, sizeof(data_buffer), &decode_len, argv[1],
			    strlen(argv[1]));
	if (ret != 0) {
		goto err;
	}

	ret = lcz_mqtt_send_string((const uint8_t *)data_buffer, topic, &mqtt_ctx.agent);

err:
	if (ret != 0) {
		shell_error(shell, ERR_MSG, ret);
	}
	return ret;
}

static void mqtt_ack_callback(int status)
{
	shell_print(shell_cur, "Send ACK: %d", status);
}

static void mqtt_connect_callback(int status)
{
	shell_print(shell_cur, "Connected: %d", status);
	mqtt_ctx.connected = true;
}

static void mqtt_disconnect_callback(int status)
{
	shell_print(shell_cur, "Disconnected: %d", status);
	mqtt_ctx.connected = false;
}

static int mqtt_shell_init(const struct device *device)
{
	mqtt_ctx.agent.ack_callback = mqtt_ack_callback;
	mqtt_ctx.agent.connect_callback = mqtt_connect_callback;
	mqtt_ctx.agent.disconnect_callback = mqtt_disconnect_callback;
	lcz_mqtt_register_user(&mqtt_ctx.agent);

	return 0;
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
/* clang-format off */
SHELL_STATIC_SUBCMD_SET_CREATE(
	mqtt_cmds,
    SHELL_CMD_ARG(connect, NULL, "Connect to MQTT broker", cmd_mqtt_connect, 1, 0),
	SHELL_CMD_ARG(disconnect, NULL, "Disconnect from MQTT broker", cmd_mqtt_disconnect, 1, 0),
	SHELL_CMD_ARG(send, NULL, "Send a Base64 encoded string to the MQTT broker", cmd_mqtt_send, 2, 0),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);
/* clang-format on */

SHELL_CMD_REGISTER(mqtt, &mqtt_cmds, "MQTT commands", NULL);

SYS_INIT(mqtt_shell_init, APPLICATION, CONFIG_LCZ_MQTT_SHELL_INIT_PRIORITY);
