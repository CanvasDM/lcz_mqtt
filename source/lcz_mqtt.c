/**
 * @file lcz_mqtt.c
 * @brief Wrapped MQTT APIs
 *
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2020-2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_mqtt, CONFIG_LCZ_MQTT_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <mbedtls/ssl.h>
#include <net/socket.h>
#include <stdio.h>
#include <kernel.h>
#include <random/rand32.h>
#include <init.h>
#include <sys/printk.h>

#include "lcz_dns.h"
#include "lcz_snprintk.h"
#include "lcz_software_reset.h"
#include "lcz_pki_auth.h"
#include "attr.h"
#include "lcz_mqtt_shadow_parser.h"
#include "errno_str.h"

#include "lcz_mqtt.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define CONNECTION_ATTEMPT_DELAY_MS 500
#define SOCKET_POLL_WAIT_TIME_MSECS 250

#define LCZ_MQTT_RX_THREAD_PRIORITY K_PRIO_COOP(15)

#if defined(CONFIG_LCZ_MQTT_STATS)
#define INCR_STAT(field) lcz_mqtt.stats.field += 1
#define RESET_STAT(field) lcz_mqtt.stats.field = 0
#define ADD_STAT(field, amount) lcz_mqtt.stats.field += (amount)
#define SET_STAT(field, amount) lcz_mqtt.stats.field = (amount)
#define GET_STAT(field) lcz_mqtt.stats.field
#else
#define INCR_STAT(field)
#define RESET_STAT(field)
#define ADD_STAT(field, amount)
#define SET_STAT(field, amount)
#define GET_STAT(field) 0
#endif

/**************************************************************************************************/
/* Global Data Definitions                                                                        */
/**************************************************************************************************/
K_MUTEX_DEFINE(lcz_mqtt_mutex);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
K_THREAD_STACK_DEFINE(rx_thread_stack, CONFIG_LCZ_MQTT_RX_THREAD_SIZE);
static struct k_thread rx_thread;

static struct k_sem connected_sem;
static struct k_sem disconnected_sem;

static uint8_t mqtt_rx_buffer[CONFIG_LCZ_MQTT_RX_BUFFER_SIZE];
static uint8_t mqtt_tx_buffer[CONFIG_LCZ_MQTT_TX_BUFFER_SIZE];
static struct mqtt_client mqtt_client_ctx;
static struct sockaddr_storage mqtt_broker;

static struct pollfd fds[1];
static int nfds;

static struct addrinfo *saddr;

#if defined(CONFIG_MQTT_LIB_TLS)
static sec_tag_t mqtt_security_tags[] = { CONFIG_LCZ_MQTT_CERT_TAG };
#endif

static struct k_work_delayable publish_watchdog;
static struct k_work_delayable keep_alive;

#if defined(CONFIG_LCZ_MQTT_SUBSCRIPTIONS)
static uint8_t subscription_buffer[CONFIG_LCZ_MQTT_SHADOW_IN_MAX_SIZE];
static uint8_t subscription_topic[CONFIG_LCZ_MQTT_SHADOW_TOPIC_MAX_SIZE];
#endif

static struct {
	bool initialized;
	bool resolved;
	bool certs_loaded;
	bool connected;
	bool disconnect_request;
	struct mqtt_utf8 user_name;
	struct mqtt_utf8 password;
	struct {
		uint32_t consecutive_connection_failures;
		uint32_t disconnects;
		uint32_t sends;
		uint32_t acks;
		uint32_t success;
		uint32_t failure;
		uint32_t consecutive_fails;
		int64_t time;
		int64_t delta;
		int64_t delta_max;
		uint32_t tx_payload_bytes;
		uint32_t rx_payload_bytes;
	} stats;
} lcz_mqtt;

static sys_slist_t callback_list;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void prepare_fds(struct mqtt_client *client);
static void clear_fds(void);
static void wait(int timeout);
static void mqtt_evt_handler(struct mqtt_client *const client, const struct mqtt_evt *evt);
static int subscription_handler(struct mqtt_client *const client, const struct mqtt_evt *evt);
static void subscription_flush(struct mqtt_client *const client, size_t length);
static int publish(struct mqtt_client *client, enum mqtt_qos qos, const uint8_t *data, uint32_t len,
		   const uint8_t *topic, bool binary, struct lcz_mqtt_user *user);
static void client_init(struct mqtt_client *client);
static int try_to_connect(struct mqtt_client *client);
static void lcz_mqtt_rx_thread(void *arg1, void *arg2, void *arg3);
static uint16_t rand16_nonzero_get(void);
static void publish_watchdog_work_handler(struct k_work *work);
static void keep_alive_work_handler(struct k_work *work);
static void log_json(const char *prefix, size_t size, const char *buffer);

static void update_ack_id(const struct lcz_mqtt_user *user, uint16_t id);
static void issue_disconnect_callbacks(void);
static void issue_ack_callback(int result, uint16_t id);

static void connect_callback(int status);
static void disconnect_callback(int status);
static bool ignore_publish_watchdog(void);
static void watchdog_timeout_callback(void);

static int connect_on_request(void);

/**************************************************************************************************/
/* Sys Init                                                                                       */
/**************************************************************************************************/
static int lcz_mqtt_init(const struct device *device)
{
	ARG_UNUSED(device);

	k_sem_init(&connected_sem, 0, 1);
	k_sem_init(&disconnected_sem, 0, 1);

	k_thread_name_set(k_thread_create(&rx_thread, rx_thread_stack,
					  K_THREAD_STACK_SIZEOF(rx_thread_stack),
					  lcz_mqtt_rx_thread, NULL, NULL, NULL,
					  LCZ_MQTT_RX_THREAD_PRIORITY, 0, K_NO_WAIT),
			  "lcz_mqtt");

	k_work_init_delayable(&publish_watchdog, publish_watchdog_work_handler);
	k_work_init_delayable(&keep_alive, keep_alive_work_handler);

	lcz_mqtt.initialized = true;
	return 0;
}

SYS_INIT(lcz_mqtt_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_mqtt_get_server_addr(void)
{
	int r;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	r = dns_resolve_server_addr(attr_get_quasi_static(ATTR_ID_mqtt_endpoint),
				    attr_get_quasi_static(ATTR_ID_mqtt_port), &hints, &saddr);

	if (r < 0) {
		lcz_mqtt.resolved = false;
		LOG_ERR("Unable to resolve server addr: %d", r);
	} else {
		lcz_mqtt.resolved = true;
		LOG_DBG("Resolve server addr status: %d", r);
	}

	return r;
}

int lcz_mqtt_connect(void)
{
	int r = 0;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);

	if (!lcz_mqtt.connected) {
		lcz_mqtt.disconnect_request = false;
		r = try_to_connect(&mqtt_client_ctx);
		if (r != 0) {
			INCR_STAT(consecutive_connection_failures);
		} else {
			RESET_STAT(consecutive_connection_failures);
		}
	}

	k_mutex_unlock(&lcz_mqtt_mutex);

	return r;
}

int lcz_mqtt_disconnect(void)
{
	if (lcz_mqtt.connected) {
		lcz_mqtt.disconnect_request = true;
		LOG_DBG("Waiting to close MQTT connection");
		k_sem_take(&disconnected_sem, K_FOREVER);
		LOG_DBG("MQTT connection closed");
	}

	return 0;
}

int lcz_mqtt_load_credentials(void)
{
	int r = -ENOTSUP;

	if (IS_ENABLED(CONFIG_MQTT_LIB_TLS)) {
		r = lcz_pki_auth_tls_credential_load(LCZ_PKI_AUTH_STORE_TELEMETRY,
						     CONFIG_LCZ_MQTT_CERT_TAG,
						     attr_get_bool(ATTR_ID_mqtt_root_only));
	}

	if (r == 0) {
		lcz_mqtt.certs_loaded = true;
	} else {
		lcz_mqtt.certs_loaded = false;
	}
	LOG_DBG("credential load: %d", r);

	return r;
}

int lcz_mqtt_unload_credentials(void)
{
	int r;

	r = lcz_pki_auth_tls_credential_unload(LCZ_PKI_AUTH_STORE_TELEMETRY,
					       CONFIG_LCZ_MQTT_CERT_TAG);
	lcz_mqtt.certs_loaded = false;

	return r;
}

int lcz_mqtt_send_string(const uint8_t *data, const uint8_t *topic, struct lcz_mqtt_user *user)
{
	return lcz_mqtt_send_data(false, data, 0, topic, user);
}

int lcz_mqtt_send_binary(const uint8_t *data, uint32_t len, const uint8_t *topic,
			 struct lcz_mqtt_user *user)
{
	return lcz_mqtt_send_data(true, data, len, topic, user);
}

int lcz_mqtt_send_data(bool binary, const uint8_t *data, uint32_t len, const uint8_t *topic,
		       struct lcz_mqtt_user *user)
{
	int r = -ENOTCONN;
	uint32_t length;

	r = connect_on_request();
	if (r < 0) {
		return r;
	}

	if (binary) {
		length = len;
	} else {
		length = strlen(data);
	}

	r = publish(&mqtt_client_ctx, attr_get_uint32(ATTR_ID_mqtt_publish_qos, 0), data, length,
		    topic, binary, user);

	INCR_STAT(sends);
	if (r == 0) {
		INCR_STAT(success);
		RESET_STAT(consecutive_fails);
		ADD_STAT(tx_payload_bytes, length);
		lcz_mqtt_restart_publish_watchdog();
	} else {
		INCR_STAT(failure);
		INCR_STAT(consecutive_fails);
		LOG_ERR("MQTT publish: %d", r);
	}

	return r;
}

bool lcz_mqtt_connected(void)
{
	return lcz_mqtt.connected;
}

#if defined(CONFIG_LCZ_MQTT_SUBSCRIPTIONS)
int lcz_mqtt_subscribe(const uint8_t *topic, uint8_t subscribe)
{
	struct mqtt_topic mt;
	int r = -EPERM;
	const char *const str = subscribe ? "Subscribed" : "Unsubscribed";
	struct mqtt_subscription_list list = { .list = &mt,
					       .list_count = 1,
					       .message_id = rand16_nonzero_get() };

	r = connect_on_request();
	if (r < 0) {
		return r;
	}

	mt.topic.utf8 = (uint8_t *)topic;
	mt.topic.size = strlen((char *)topic);
	mt.qos = attr_get_uint32(ATTR_ID_mqtt_subscribe_qos, 0);
	__ASSERT(mt.topic.size != 0, "Invalid topic");
	r = subscribe ? mqtt_subscribe(&mqtt_client_ctx, &list) :
			      mqtt_unsubscribe(&mqtt_client_ctx, &list);
	if (r != 0) {
		LOG_ERR("%s status %d to %s", str, r, (char *)topic);
	} else {
		LOG_INF("%s to %s", str, (char *)topic);
	}
	return r;
}
#endif

void lcz_mqtt_register_user(struct lcz_mqtt_user *user)
{
	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	sys_slist_append(&callback_list, &user->node);
	k_mutex_unlock(&lcz_mqtt_mutex);
}

int lcz_mqtt_shadow_format_and_send(struct lcz_mqtt_user *user, const char *topic, const char *fmt,
				    ...)
{
	va_list ap;
	char *msg = NULL;
	int actual_size;
	int req_size;
	int r;

	va_start(ap, fmt);
	do {
		/* determine size of message */
		req_size = vsnprintk(msg, 0, fmt, ap);
		if (req_size < 0) {
			LOG_ERR("Invalid format or arguments");
			r = -EINVAL;
			break;
		}
		/* add one for null character */
		req_size += 1;

		msg = k_calloc(req_size, sizeof(char));
		if (msg == NULL) {
			LOG_ERR("Unable to allocate message");
			r = -ENOMEM;
			break;
		} else {
			LOG_DBG("MQTT shadow size %d", req_size);
		}

		/* build actual message and try to send it */
		actual_size = vsnprintk(msg, req_size, fmt, ap);

		if (actual_size > 0 && actual_size < req_size) {
			r = lcz_mqtt_send_string((uint8_t*)msg, (uint8_t*)topic, user);
		} else {
			LOG_ERR("Unable to format (and send) MQTT message");
			r = -EINVAL;
		}

	} while (0);

	va_end(ap);
	k_free(msg);
	return r;
}

int lcz_mqtt_topic_format(char *topic, size_t max_size, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);

	r = vsnprintk(topic, max_size, fmt, ap);
	if (r < 0) {
		LOG_ERR("Error encoding topic string");
	} else if (r >= max_size) {
		LOG_ERR("Topic string too small %d (desired) >= %d (max)", r, max_size);
		r = -EINVAL;
	} else {
		r = 0;
	}

	va_end(ap);
	return r;
}

int lcz_mqtt_restart_publish_watchdog(void)
{
	if (!lcz_mqtt.initialized) {
		return -EBUSY;
	}

	uint32_t timeout = attr_get_uint32(ATTR_ID(mqtt_watchdog), 0);
	if (timeout == 0) {
		k_work_cancel_delayable(&publish_watchdog);
	} else {
		k_work_reschedule(&publish_watchdog, K_SECONDS(timeout));
	}

	return 0;
}

int attr_prepare_mqtt_watchdog_remaining(void)
{
	return attr_set_uint32(ATTR_ID(mqtt_watchdog_remaining),
			       k_work_delayable_remaining_get(&publish_watchdog) /
				       CONFIG_SYS_CLOCK_TICKS_PER_SEC);
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void prepare_fds(struct mqtt_client *client)
{
	if (client->transport.type == MQTT_TRANSPORT_NON_SECURE) {
		fds[0].fd = client->transport.tcp.sock;
	}
#if defined(CONFIG_MQTT_LIB_TLS)
	else if (client->transport.type == MQTT_TRANSPORT_SECURE) {
		fds[0].fd = client->transport.tls.sock;
	}
#endif

	fds[0].events = ZSOCK_POLLIN;
	nfds = 1;
}

static void clear_fds(void)
{
	fds[0].fd = 0;
	nfds = 0;
}

static void wait(int timeout)
{
	if (nfds > 0) {
		if (poll(fds, nfds, timeout) < 0) {
			LOG_ERR("poll error: %d", errno);
		}
	}
}

static void mqtt_evt_handler(struct mqtt_client *const client, const struct mqtt_evt *evt)
{
	int r;

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		connect_callback(evt->result);
		if (evt->result != 0) {
			LOG_ERR("MQTT connect failed %d", evt->result);
			break;
		}

		lcz_mqtt.connected = true;
		k_sem_give(&connected_sem);
		LOG_INF("MQTT client connected!");
		k_work_reschedule(&keep_alive, K_NO_WAIT);
		break;

	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT client disconnected %d", evt->result);
		lcz_mqtt.connected = false;
		lcz_mqtt.disconnect_request = true;
		k_work_cancel_delayable(&keep_alive);
		INCR_STAT(disconnects);
		disconnect_callback(evt->result);
		break;

	case MQTT_EVT_PUBACK:
		issue_ack_callback(evt->result, evt->param.puback.message_id);

		if (evt->result != 0) {
			LOG_ERR("MQTT PUBACK error %d", evt->result);
			break;
		}

		/* Delta may not be valid when there are multiple publishers */
		INCR_STAT(acks);
		SET_STAT(delta, k_uptime_delta(&lcz_mqtt.stats.time));
		SET_STAT(delta_max, MAX(lcz_mqtt.stats.delta_max, lcz_mqtt.stats.delta));

		LOG_DBG("PUBACK packet id: %u delta: %d", evt->param.puback.message_id,
			(int32_t)GET_STAT(delta));

		break;

	case MQTT_EVT_SUBACK:
		LOG_DBG("SUBACK packet id: %u result: %d", evt->param.suback.message_id,
			evt->result);
		break;

	case MQTT_EVT_PUBLISH:
		if (evt->result != 0) {
			LOG_ERR("MQTT PUBLISH error %d", evt->result);
			break;
		}
		r = subscription_handler(client, evt);
		if ((r >= 0) && (r < evt->param.publish.message.payload.len)) {
			subscription_flush(client, evt->param.publish.message.payload.len - r);
		}
		break;
	default:
		break;
	}
}

/* Large strings (474 bytes+) are not printed when using LOG_X */
static void log_json(const char *prefix, size_t size, const char *buffer)
{
	if (buffer[size] == 0) {
		printk("%s size: %u data: %s\r\n", prefix, size, buffer);
	} else {
		LOG_ERR("Logging JSON as a string requires NULL terminator");
	}
}

/* The timestamps can make the shadow size larger than 4K.
 * A static buffer is used for processing.
 */
static int subscription_handler(struct mqtt_client *const client, const struct mqtt_evt *evt)
{
	int r = 0;

#if defined(CONFIG_LCZ_MQTT_SUBSCRIPTIONS)
	uint16_t id = evt->param.publish.message_id;
	uint32_t length = evt->param.publish.message.payload.len;
	uint8_t qos = evt->param.publish.message.topic.qos;
	const uint8_t *topic = evt->param.publish.message.topic.topic.utf8;
	uint32_t topic_length = evt->param.publish.message.topic.topic.size;

	/* Terminate topic and shadow so that they can be printed and used
	 * as strings by other modules.
	 */

	size_t size = length + 1;
	if (size > CONFIG_LCZ_MQTT_SHADOW_IN_MAX_SIZE) {
		LOG_ERR("Shadow buffer too small");
		return 0;
	}

	if (topic_length + 1 > CONFIG_LCZ_MQTT_SHADOW_IN_MAX_SIZE) {
		LOG_ERR("Shadow topic too small");
		return 0;
	} else {
		memcpy(subscription_topic, topic, topic_length);
		subscription_topic[topic_length] = 0;
	}

	LOG_INF("MQTT RXd ID: %d payload len: %d", id, length);
	if (IS_ENABLED(CONFIG_LCZ_MQTT_LOG_MQTT_SUBSCRIPTION_TOPIC)) {
		log_json("Subscription topic", topic_length, subscription_topic);
	}

	ADD_STAT(rx_payload_bytes, length);

	r = mqtt_read_publish_payload(client, subscription_buffer, length);
	if (r == length) {
		subscription_buffer[length] = 0; /* null terminate */

		if (IS_ENABLED(CONFIG_LCZ_MQTT_LOG_MQTT_SUBSCRIPTION)) {
			log_json("Subscription data", r, subscription_buffer);
		}

		if (IS_ENABLED(CONFIG_LCZ_MQTT_SHADOW_PARSER)) {
			lcz_mqtt_shadow_parser(subscription_topic, subscription_buffer);
		}

		lcz_mqtt_subscription_callback(subscription_topic, subscription_buffer);

		if (qos == MQTT_QOS_1_AT_LEAST_ONCE) {
			struct mqtt_puback_param param = { .message_id = id };
			(void)mqtt_publish_qos1_ack(client, &param);
		} else if (qos == MQTT_QOS_2_EXACTLY_ONCE) {
			LOG_ERR("QOS 2 not supported");
		}
	}
#endif

	return r;
}

static void subscription_flush(struct mqtt_client *const client, size_t length)
{
	LOG_ERR("Subscription Flush %u", length);
	char junk;
	size_t i;
	for (i = 0; i < length; i++) {
		if (mqtt_read_publish_payload(client, &junk, 1) != 1) {
			break;
		}
	}
}

static int publish(struct mqtt_client *client, enum mqtt_qos qos, const uint8_t *data, uint32_t len,
		   const uint8_t *topic, bool binary, struct lcz_mqtt_user *user)
{
	struct mqtt_publish_param param;

	memset(&param, 0, sizeof(struct mqtt_publish_param));
	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = (uint8_t *)topic;
	param.message.topic.topic.size = strlen((char *)topic);
	param.message.payload.data = (uint8_t *)data;
	param.message.payload.len = len;
	param.message_id = rand16_nonzero_get();
	param.dup_flag = 0U;
	param.retain_flag = 0U;

	if (IS_ENABLED(CONFIG_LCZ_MQTT_LOG_MQTT_PUBLISH_TOPIC)) {
		log_json("Publish Topic", param.message.topic.topic.size, topic);
	}

	if (!binary && IS_ENABLED(CONFIG_LCZ_MQTT_LOG_MQTT_PUBLISH)) {
		log_json("Publish string", len, data);
	}

	if (mqtt_client_ctx.tx_buf_size < len) {
		LOG_WRN("len: %u", len);
	}

	SET_STAT(time, k_uptime_get());

	update_ack_id(user, param.message_id);

	return mqtt_publish(client, &param);
}

static void broker_init(void)
{
	struct sockaddr_in *broker4 = (struct sockaddr_in *)&mqtt_broker;

	broker4->sin_family = saddr->ai_family;
	broker4->sin_port = htons(strtol(attr_get_quasi_static(ATTR_ID_mqtt_port), NULL, 0));
	net_ipaddr_copy(&broker4->sin_addr, &net_sin(saddr->ai_addr)->sin_addr);
}

static void client_init(struct mqtt_client *client)
{
	const char *s;

	broker_init();

	/* MQTT client configuration */
	mqtt_client_init(client);
	client->broker = &mqtt_broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = lcz_mqtt_get_mqtt_client_id();
	client->client_id.size = strlen((char *)client->client_id.utf8);
	client->user_name = NULL;
	client->password = NULL;
	client->clean_session = attr_get_bool(ATTR_ID_mqtt_clean_session) ? 1 : 0;

	/* If name isn't empty, then use it */
	s = attr_get_quasi_static(ATTR_ID_mqtt_user_name);
	if (strlen(s) > 0) {
		lcz_mqtt.user_name.utf8 = (uint8_t *)s;
		lcz_mqtt.user_name.size = strlen(s);
		client->user_name = &lcz_mqtt.user_name;
	}

	/* If client password isn't empty, then use it */
	s = attr_get_quasi_static(ATTR_ID_mqtt_password);
	if (strlen(s) > 0) {
		lcz_mqtt.password.utf8 = (uint8_t *)s;
		lcz_mqtt.password.size = strlen(s);
		client->password = &lcz_mqtt.password;
	}

	/* MQTT buffers configuration */
	client->rx_buf = mqtt_rx_buffer;
	client->rx_buf_size = sizeof(mqtt_rx_buffer);
	client->tx_buf = mqtt_tx_buffer;
	client->tx_buf_size = sizeof(mqtt_tx_buffer);

	/* MQTT transport configuration */
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
	if (attr_get_bool(ATTR_ID_mqtt_transport_secure)) {
#if defined(CONFIG_MQTT_LIB_TLS)
		client->transport.type = MQTT_TRANSPORT_SECURE;

		struct mqtt_sec_config *tls_config = &client->transport.tls.config;
		tls_config->peer_verify =
			attr_get_uint32(ATTR_ID_mqtt_peer_verify, MBEDTLS_SSL_VERIFY_NONE);
		tls_config->cipher_count = 0;
		tls_config->cipher_list = NULL;
		tls_config->sec_tag_list = mqtt_security_tags;
		tls_config->sec_tag_count = ARRAY_SIZE(mqtt_security_tags);
		tls_config->session_cache = TLS_SESSION_CACHE_DISABLED;
		tls_config->hostname = attr_get_quasi_static(ATTR_ID_mqtt_endpoint);
#else
		LOG_WRN("MQTT LIB TLS not enabled - using non-secure");
#endif
	}
}

/* In this routine we block until the connected variable is 1 */
static int try_to_connect(struct mqtt_client *client)
{
	int r;

	if (lcz_mqtt.connected) {
		return 0;
	}

	client_init(client);
	LOG_INF("Attempting to connect %s to MQTT Broker %s", (char *)client->client_id.utf8,
		(char *)attr_get_quasi_static(ATTR_ID_mqtt_endpoint));
	r = mqtt_connect(client);
	if (r != 0) {
		LOG_ERR("mqtt_connect: %d", r);
	}

	prepare_fds(client);
	wait(CONNECTION_ATTEMPT_DELAY_MS);
	mqtt_input(client);

	if (!lcz_mqtt.connected) {
		mqtt_abort(client);
	}

	if (lcz_mqtt.connected) {
		return 0;
	} else {
		return -EINVAL;
	}
}

static void lcz_mqtt_rx_thread(void *arg1, void *arg2, void *arg3)
{
	while (true) {
		if (lcz_mqtt.connected) {
			/* Wait for socket RX data */
			wait(SOCKET_POLL_WAIT_TIME_MSECS);
			/* Process MQTT RX data */
			if ((fds[0].revents & POLLIN) == POLLIN) {
				mqtt_input(&mqtt_client_ctx);
			}
			/* Disconnect request is set from the disconnect callback
			 * and from a user request.
			 */
			if (lcz_mqtt.disconnect_request) {
				LOG_DBG("Closing MQTT connection");
				mqtt_disconnect(&mqtt_client_ctx);
				clear_fds();
				lcz_mqtt.disconnect_request = false;
				lcz_mqtt.connected = false;
				k_sem_give(&disconnected_sem);
				issue_disconnect_callbacks();
			}
		} else {
			LOG_DBG("Waiting for MQTT connection...");
			/* Wait for connection */
			k_sem_reset(&connected_sem);
			k_sem_take(&connected_sem, K_FOREVER);
		}
	}
}

/* Message ID of zero is reserved as invalid. */
static uint16_t rand16_nonzero_get(void)
{
	uint16_t r = 0;

	do {
		r = (uint16_t)sys_rand32_get();
	} while (r == 0);

	return r;
}

static void publish_watchdog_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	uint32_t timeout = attr_get_uint32(ATTR_ID(mqtt_watchdog), 0);
	bool ignore;

	if (timeout == 0) {
		return;
	}

	ignore = ignore_publish_watchdog();

	LOG_WRN("Unable to publish MQTT in the last %u seconds %s", timeout,
		ignore ? "(ignored)" : "");

	if (ignore) {
		lcz_mqtt_restart_publish_watchdog();
	} else {
		watchdog_timeout_callback();
		lcz_software_reset_after_assert(0);
	}
}

static void keep_alive_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	int time_left;
	k_timeout_t delay;
	int r;

	/* The accuracy of mqtt_live may not be good enough to support
	 * the broker's maximum keep alive timeout.
	 *
	 * For example, the absolute maximum of Losant is 20 minutes +/- 10 seconds.
	 * If the keep alive is set to 1200, then disconnections will occur.
	 * If the keep alive is set to 1170 (19.5 minutes), then the Losant timeout
	 * will be 20 minutes and disconnects will not occur.
	 * If the keep alive is set to 120 (2 minutes), then the actual timeout is
	 * 3 minutes.
	 */
	if (lcz_mqtt.connected) {
		r = mqtt_live(&mqtt_client_ctx);
		if (r != 0 && r != -EAGAIN) {
			LOG_ERR("mqtt_live error: %s", ERRNO_STR(r));
		} else if (IS_ENABLED(CONFIG_LCZ_MQTT_KEEP_ALIVE_VERBOSE)) {
			LOG_INF("mqtt_live status: %s",
				(r == -EAGAIN) ? "try again" : ERRNO_STR(r));
		}

		if (CONFIG_MQTT_KEEPALIVE != 0) {
			time_left = mqtt_keepalive_time_left(&mqtt_client_ctx);
			delay = K_MSEC(time_left);
			k_work_reschedule(&keep_alive, delay);
			if (IS_ENABLED(CONFIG_LCZ_MQTT_KEEP_ALIVE_VERBOSE)) {
				LOG_INF("Scheduled next keep alive: %d ms", time_left);
			}
		}
	} else if (IS_ENABLED(CONFIG_LCZ_MQTT_KEEP_ALIVE_VERBOSE)) {
		LOG_INF("MQTT Not Connected - Keep alive not sent");
	}
}

static void update_ack_id(const struct lcz_mqtt_user *user, uint16_t id)
{
	struct lcz_mqtt_user *iterator;
	bool found;

	if (user == NULL) {
		return;
	}

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (user == iterator) {
			iterator->ack_id = id;
			if (user->ack_callback == NULL) {
				LOG_WRN("Ack Callback is null");
			}
			found = true;
			break;
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);

	if (!found) {
		LOG_ERR("User not found");
	}
}

/* When disconnected, set ID to zero and notify users of failure to send. */
static void issue_disconnect_callbacks(void)
{
	struct lcz_mqtt_user *iterator;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		iterator->ack_id = 0;
		if (iterator->ack_callback != NULL) {
			iterator->ack_callback(-ENOTCONN);
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);
}

static void issue_ack_callback(int result, uint16_t id)
{
	struct lcz_mqtt_user *iterator;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->ack_id == id) {
			if (id == 0) {
				LOG_ERR("Invalid ID in user callback");
			}
			if (iterator->ack_callback != NULL) {
				if (result == 0) {
					iterator->ack_callback(id);
				} else {
					iterator->ack_callback(result);
				}
			}
			iterator->ack_id = 0;
			break;
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);
}

static void connect_callback(int status)
{
	struct lcz_mqtt_user *iterator;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->connect_callback != NULL) {
			iterator->connect_callback(status);
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);
}

static void disconnect_callback(int status)
{
	struct lcz_mqtt_user *iterator;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->disconnect_callback != NULL) {
			iterator->disconnect_callback(status);
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);
}

static bool ignore_publish_watchdog(void)
{
	struct lcz_mqtt_user *iterator;
	bool ignore = false;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->ignore_publish_watchdog != NULL) {
			if (iterator->ignore_publish_watchdog()) {
				ignore = true;
				break;
			}
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);

	return ignore;
}

static void watchdog_timeout_callback(void)
{
	struct lcz_mqtt_user *iterator;

	k_mutex_lock(&lcz_mqtt_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->watchdog_timeout_callback != NULL) {
			iterator->watchdog_timeout_callback();
		}
	}
	k_mutex_unlock(&lcz_mqtt_mutex);
}

static int connect_on_request(void)
{
	int r = -ENOTCONN;

	do {
		if (lcz_mqtt.connected) {
			r = 0;
			break;
		}

		if (!attr_get_bool(ATTR_ID_mqtt_connect_on_request)) {
			break;
		}

		if (attr_get_bool(ATTR_ID_mqtt_transport_secure)) {
			if (!lcz_mqtt.certs_loaded) {
				r = lcz_mqtt_load_credentials();
				if (r < 0) {
					break;
				}
			}
		}

		if (!lcz_mqtt.resolved) {
			r = lcz_mqtt_get_server_addr();
			LOG_DBG("get server addr: %d", r);
			if (r != 0) {
				break;
			}
		}

		r = lcz_mqtt_connect();

	} while (0);

	return r;
}

/**************************************************************************************************/
/* These can be overridden in application                                                         */
/**************************************************************************************************/
__weak const uint8_t *lcz_mqtt_get_mqtt_client_id(void)
{
	const uint8_t *result = attr_get_quasi_static(ATTR_ID_mqtt_id);

#if defined(ATTR_ID_mqtt_randomize_client_id)
	int r;
	uint8_t buffer[ATTR_MQTT_CLIENT_ID_RANDOM_MAX_STR_SIZE];

	if (attr_get_bool(ATTR_ID_mqtt_randomize_client_id)) {
		r = LCZ_SNPRINTK(buffer, "%s_%08x", result, sys_rand32_get());
		if (r > 0) {
			if (attr_set_string(ATTR_ID_mqtt_id_random, buffer, r) == 0) {
				result = attr_get_quasi_static(ATTR_ID_mqtt_id_random);
			}
		}
	}
#endif

	return result;
}

__weak void lcz_mqtt_subscription_callback(const uint8_t *topic, const uint8_t *data)
{
	return;
}