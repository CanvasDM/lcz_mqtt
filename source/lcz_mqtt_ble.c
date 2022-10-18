/**
 * @file lcz_mqtt_ble.c
 * @brief Process BLE advertisements for Laird Connectivity sensors,
 * add MQTT object instances, and update resource instances when values change.
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(mqtt_ble, CONFIG_LCZ_MQTT_BLE_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr.h>
#include <init.h>
#include <bluetooth/addr.h>
#include <sys/util.h>

#include "attr.h"
#include "lcz_lwm2m_gateway_obj.h"
#include "lcz_mqtt.h"
#include "lcz_bt_scan.h"
#include "lcz_sensor_event.h"
#include "lcz_sensor_adv_format.h"
#include "lcz_sensor_adv_match.h"
#include "lcz_snprintk.h"

#if defined(CONFIG_LCZ_MQTT_BLE_LED)
#include "lcz_led.h"
#include "led_config.h"
#endif

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define LIFETIME CONFIG_LCZ_MQTT_BLE_EVENT_TIMEOUT_SECONDS
#define MAX_INSTANCES CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES

/* prefix + postfix + nul */
#define AD_OVERHEAD_SIZE                                                                           \
	(ATTR_MQTT_BLE_PREFIX_MAX_STR_SIZE + ATTR_MQTT_BLE_POSTFIX_MAX_STR_SIZE + 1)

#define AD_LIST_SIZE CONFIG_LCZ_MQTT_BLE_AD_LIST_SIZE

struct ble_sensor {
	uint8_t last_record_type;
	uint16_t last_event_id;
};

struct stats {
	uint32_t ads;
	uint32_t legacy_ads;
	uint32_t rsp_ads;
	uint32_t coded_ads;
	uint32_t name_updates;
	uint32_t accepted_ads;
	uint32_t indexed_ads;
	uint32_t processed_ads;
	uint32_t appended_ads;
	uint32_t publish_collisions;
	uint32_t publishes;
	uint32_t ads_to_publish;
	uint32_t postfix_flush;
};

#if defined(CONFIG_LCZ_MQTT_BLE_STATS)
#define INCR_STAT(field) mb.stats.field += 1
#define RESET_STAT(field) mb.stats.field = 0
#else
#define INCR_STAT(field)
#define RESET_STAT(field)
#endif

static struct bt_le_scan_param scan_parameters = BT_LE_SCAN_PARAM_INIT(
	BT_LE_SCAN_TYPE_ACTIVE, (BT_LE_SCAN_OPT_CODED | BT_LE_SCAN_OPT_FILTER_DUPLICATE),
	CONFIG_LCZ_BT_SCAN_DEFAULT_INTERVAL, CONFIG_LCZ_BT_SCAN_DEFAULT_WINDOW);

/* Size of string to hold advertisement as hexadecimal string */
#define AD_STRING_LEN (LCZ_SENSOR_MSD_AD_PAYLOAD_LENGTH * 2)
#define AD_STRING_SIZE (AD_STRING_LEN + 1)

struct ad_list {
	uint8_t data[AD_OVERHEAD_SIZE + AD_LIST_SIZE];
	size_t index;
	size_t postfix_index;
	struct k_sem sem;
};

struct mqtt_ble {
	int scan_user_id;
	bool table_full;
	bool restart;
	struct ble_sensor table[MAX_INSTANCES];
#if defined(CONFIG_LCZ_MQTT_BLE_STATS)
	struct stats stats;
#endif
	struct lcz_mqtt_user agent;
	bool mqtt_connected;
	struct k_work_delayable publish_work;
	struct ad_list ad_list;
};

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct mqtt_ble mb;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int get_index(const bt_addr_le_t *addr, bool add);
static bool valid_index(int idx);

static void ad_handler(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
		       struct net_buf_simple *ad);
static bool ad_discard(LczSensorAdEvent_t *p);
static int ad_filter(const bt_addr_le_t *addr, LczSensorAdEvent_t *p, int8_t rssi);
static int ad_process(int idx, LczSensorAdEvent_t *p, int8_t rssi);

static void name_handler(const bt_addr_le_t *addr, struct net_buf_simple *ad);

static void gateway_obj_deleted_callback(int idx, void *data_ptr);

#if defined(CONFIG_LCZ_MQTT_BLE_LOG_LEVEL_DBG)
static const char *get_name(int idx);
#endif

static void mqtt_ack_callback(int status);
static void mqtt_connect_callback(int status);
static void mqtt_disconnect_callback(int status);

static void publish_list(struct k_work *work);
static void reschedule_publish(k_timeout_t delay);
static int append_ad_list(LczSensorAdEvent_t *p);
static int append_str(const char *str, bool quote);
static int add_delimiter(void);
static int add_prefix(void);
static int add_postfix(void);
static void discard_postfix(void);
static void flush_ad_list(void);

/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_mqtt_ble_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	int r;

	k_sem_init(&mb.ad_list.sem, 1, 1);

	if (!lcz_bt_scan_register(&mb.scan_user_id, ad_handler)) {
		LOG_ERR("MQTT sensor module failed to register with scan module");
	}

	r = lcz_bt_scan_update_parameters(mb.scan_user_id, &scan_parameters);
	if (r < 0) {
		LOG_ERR("Unable to update scan parameters: %d", r);
	}
	r = lcz_bt_scan_start(mb.scan_user_id);
	if (r < 0) {
		LOG_ERR("Unable to start scanning: %d", r);
	}

	/* Clear table full flag when object is deleted */
	lcz_lwm2m_gw_obj_set_telem_delete_cb(gateway_obj_deleted_callback);

	mb.agent.ack_callback = mqtt_ack_callback;
	mb.agent.connect_callback = mqtt_connect_callback;
	mb.agent.disconnect_callback = mqtt_disconnect_callback;
	lcz_mqtt_register_user(&mb.agent);

	k_work_init_delayable(&mb.publish_work, publish_list);
	reschedule_publish(K_SECONDS(CONFIG_LCZ_MQTT_BLE_FIRST_PUBLISH));

	return 0;
}

SYS_INIT(lcz_mqtt_ble_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

/**************************************************************************************************/
/* Occurs in BT RX Thread context                                                                 */
/**************************************************************************************************/
static void ad_handler(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
		       struct net_buf_simple *ad)
{
	LczSensorAdCoded_t *coded;
	AdHandle_t handle;

	INCR_STAT(ads);

	/* Sensor enable is a control point that can be used to indicate that
	 * the gateway has been commissioned.
	 * Here it is used to prevent processing of ads and to reload certs.
	 */
	if (!attr_get_bool(ATTR_ID_mqtt_ble_enable)) {
		if (!mb.restart) {
			/* Disconnect and connect in system workq thread instead of callback */
			reschedule_publish(K_NO_WAIT);
			lcz_mqtt_unload_credentials();
			mb.restart = true;
		}
		return;
	}

	if (mb.restart) {
		if (k_sem_take(&mb.ad_list.sem, K_NO_WAIT) == 0) {
			flush_ad_list();
			k_sem_give(&mb.ad_list.sem);
			reschedule_publish(K_SECONDS(CONFIG_LCZ_MQTT_PUBLISH_RATE));
			mb.restart = false;
		}
	}

	handle = AdFind_Type(ad->data, ad->len, BT_DATA_MANUFACTURER_DATA, BT_DATA_INVALID);

	/* Only one of these types can occur at a time. */

	if (lcz_sensor_adv_match_1m(&handle)) {
		INCR_STAT(legacy_ads);
		ad_filter(addr, (LczSensorAdEvent_t *)handle.pPayload, rssi);
		return;
	}

	if (lcz_sensor_adv_match_coded(&handle)) {
		INCR_STAT(coded_ads);
		/* The coded phy contains the TLVs of the 1M ad and scan response */
		coded = (LczSensorAdCoded_t *)handle.pPayload;
		ad_filter(addr, &coded->ad, rssi);
		name_handler(addr, ad);
		return;
	}

	if (lcz_sensor_adv_match_rsp(&handle)) {
		INCR_STAT(rsp_ads);
		name_handler(addr, ad);
		return;
	}
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static bool valid_index(int idx)
{
	return (idx >= 0 && idx < MAX_INSTANCES);
}

static int get_index(const bt_addr_le_t *addr, bool add)
{
	static char addr_str[BT_ADDR_LE_STR_LEN];
	int idx;

	/* If the device isn't in the database,
	 * the ad has been filtered, the table isn't full, and it isn't blocked;
	 * try to add it.
	 */
	idx = lcz_lwm2m_gw_obj_lookup_ble(addr);
	if (!valid_index(idx) && add && !mb.table_full) {
		bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
		idx = lcz_lwm2m_gw_obj_create(addr);
		/* Limit logging for blocked devices */
		if (idx != -EPERM || IS_ENABLED(CONFIG_LCZ_MQTT_BLE_CREATE_LOG_VERBOSE)) {
			LOG_DBG("Gateway object create request %s: idx: %d inst: %d name: %s",
				addr_str, idx, lcz_lwm2m_gw_obj_get_instance(idx), get_name(idx));
		}
		if (idx == -ENOMEM) {
			mb.table_full = true;
		}
	}

	if (idx >= MAX_INSTANCES) {
		LOG_ERR("Invalid index");
		return -EPERM;
	}

	return idx;
}

static int ad_filter(const bt_addr_le_t *addr, LczSensorAdEvent_t *p, int8_t rssi)
{
	int idx = -EPERM;

	do {
		if (p == NULL) {
			break;
		}

		if (ad_discard(p)) {
			break;
		}

		INCR_STAT(accepted_ads);
		idx = get_index(addr, true);
		if (!valid_index(idx)) {
			break;
		}
		INCR_STAT(indexed_ads);

		/* Filter out duplicate events. */
		if ((p->id == mb.table[idx].last_event_id) &&
		    (p->recordType == mb.table[idx].last_record_type)) {
			break;
		}

		if (IS_ENABLED(CONFIG_LCZ_MQTT_BLE_EVENT_LOG_VERBOSE)) {
			LOG_INF("%s idx: %d RSSI: %d id: %u",
				lcz_sensor_event_get_string(p->recordType), idx, rssi, p->id);
		}

		if (ad_process(idx, p, rssi) == 0) {
			mb.table[idx].last_event_id = p->id;
			mb.table[idx].last_record_type = p->recordType;

#if defined(CONFIG_LCZ_MQTT_BLE_LED)
			lcz_led_blink(BLE_LED, &BLE_ACTIVITY_LED_PATTERN);
#endif
		}

		if (lcz_lwm2m_gw_obj_set_lifetime(idx, LIFETIME) != 0) {
			LOG_ERR("Unable to set lifetime");
		}

	} while (0);

	return idx;
}

/* If filter is non-zero, then network ID in advertisement must match or
 * it will be discarded.
 */
static bool ad_discard(LczSensorAdEvent_t *p)
{
	uint16_t network_id = (uint16_t)attr_get_uint32(ATTR_ID_mqtt_ble_network_id_filter, 0);

	if (network_id == 0) {
		return false;
	} else if (network_id == p->networkId) {
		return false;
	} else {
		return true;
	}
}

static int ad_process(int idx, LczSensorAdEvent_t *p, int8_t rssi)
{
	int r = 0;

	/* If a publish is in progress, then try again later.
	 * Default configuration of Laird sensors is to publish each event
	 * for 10-15 seconds.
	 */
	if (k_sem_take(&mb.ad_list.sem, K_NO_WAIT) == 0) {
		INCR_STAT(processed_ads);
		if (append_ad_list(p) == 0) {
			INCR_STAT(appended_ads);
		}

		k_sem_give(&mb.ad_list.sem);
	} else {
		INCR_STAT(publish_collisions);
		r = -EBUSY;
	}

	return r;
}

static int append_str(const char *str, bool quote)
{
	int r = 0;
	size_t len = strlen(str);

	if (len == 0) {
		/* don't do anything */
	} else if ((mb.ad_list.index + len + (quote ? 2 : 0)) < sizeof(mb.ad_list.data) - 1) {
		if (quote) {
			mb.ad_list.data[mb.ad_list.index++] = '"';
		}
		memcpy(&mb.ad_list.data[mb.ad_list.index], str, len);
		mb.ad_list.index += len;
		if (quote) {
			mb.ad_list.data[mb.ad_list.index++] = '"';
		}
		/* Publish (and logging) require a terminated string */
		mb.ad_list.data[mb.ad_list.index] = '\0';
	} else {
		LOG_ERR("Unable to append to AD list size: %u", len);
		r = -ENOMEM;
	}

	return r;
}

static void flush_ad_list(void)
{
	mb.ad_list.index = 0;
	mb.ad_list.postfix_index = 0;
	RESET_STAT(ads_to_publish);
}

static int add_delimiter(void)
{
	return append_str(attr_get_quasi_static(ATTR_ID_mqtt_ble_delimiter), false);
}

static int add_prefix(void)
{
	return append_str(attr_get_quasi_static(ATTR_ID_mqtt_ble_prefix), false);
}

static int add_postfix(void)
{
	/* save index for use if publish fails */
	mb.ad_list.postfix_index = mb.ad_list.index;

	return append_str(attr_get_quasi_static(ATTR_ID_mqtt_ble_postfix), false);
}

static void discard_postfix(void)
{
	mb.ad_list.index = mb.ad_list.postfix_index;
}

static int append_ad_list(LczSensorAdEvent_t *p)
{
	uint8_t hex_chunk[AD_STRING_SIZE];
	size_t len;
	int r = 0;

	do {
		if (mb.ad_list.index == 0) {
			r = add_prefix();
		} else {
			r = add_delimiter();
		}
		if (r < 0) {
			break;
		}

		/* Compare against list size (not .data size) so that there is
		 * always room for prefix and postfix.
		 */
		if ((mb.ad_list.index + AD_STRING_LEN) > AD_LIST_SIZE) {
			r = -ENOMEM;
			LOG_ERR("AD list full");
			reschedule_publish(K_NO_WAIT);
			break;
		}

		len = bin2hex((uint8_t *)p, sizeof(LczSensorAdEvent_t), hex_chunk, AD_STRING_SIZE);
		if (len == AD_STRING_LEN) {
			r = append_str(hex_chunk, attr_get_bool(ATTR_ID_mqtt_ble_quote));
		} else {
			LOG_ERR("Unexpected ad length %d", len);
			r = -EINVAL;
		}
		if (r < 0) {
			break;
		}

		INCR_STAT(ads_to_publish);

		if (mb.ad_list.index >= CONFIG_LCZ_MQTT_BLE_PUBLISH_THRESHOLD) {
			LOG_DBG("Ad list publish threshold met");
			reschedule_publish(K_NO_WAIT);
		}

	} while (0);

	return r;
}

static void publish_list(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct mqtt_ble *p = CONTAINER_OF(dwork, struct mqtt_ble, publish_work);
	int r;
	__ASSERT(p != &mb, LOG_ERR("Invalid pointer"));

	if (!attr_get_bool(ATTR_ID_mqtt_ble_enable)) {
		lcz_mqtt_disconnect();
		return;
	}

	reschedule_publish(K_SECONDS(CONFIG_LCZ_MQTT_PUBLISH_RATE));

	if (p->ad_list.index == 0) {
		LOG_DBG("Nothing to send");
		return;
	}

	k_sem_take(&mb.ad_list.sem, K_FOREVER);

	r = add_postfix();
	if (r < 0) {
		/* If the postfix can't be added then flush the list (this shouldn't happen) */
		LOG_ERR("%s can't append postfix to ad buffer", __func__);
		INCR_STAT(postfix_flush);
		flush_ad_list();
	} else {
		r = lcz_mqtt_send_string(p->ad_list.data,
					 attr_get_quasi_static(ATTR_ID_mqtt_ble_topic), &p->agent);
		if (r < 0) {
			LOG_ERR("%s status: %d", __func__, r);
		} else {
			INCR_STAT(publishes);
			LOG_DBG("status: %d", r);
		}
	}

	if (attr_get_uint32(ATTR_ID_mqtt_publish_qos, 0) == 0) {
		/* Ack requires qos 1 (or 2) */
		flush_ad_list();
		k_sem_give(&mb.ad_list.sem);
	} else if (r < 0) {
		/* Free on error, otherwise wait for publish ack. */
		discard_postfix();
		k_sem_give(&mb.ad_list.sem);
	}
}

static void reschedule_publish(k_timeout_t delay)
{
	int r;

	r = k_work_reschedule(&mb.publish_work, delay);
	if (r < 0) {
		LOG_ERR("Unable to schedule MQTT AD publish: %d", r);
	}
}

static void name_handler(const bt_addr_le_t *addr, struct net_buf_simple *ad)
{
	AdHandle_t handle;
	int idx;
	int r;

	idx = get_index(addr, false);
	if (!valid_index(idx)) {
		return;
	}

	handle = AdFind_Name(ad->data, ad->len);
	if (handle.pPayload == NULL) {
		return;
	}

	/* If the LwM2M connection has been proxied or named already, then don't try to set name. */
	if (lcz_lwm2m_gw_obj_inst_created(idx)) {
		return;
	}

	r = lcz_lwm2m_gw_obj_set_endpoint_name(idx, handle.pPayload, handle.size);
	if (r == 0) {
		INCR_STAT(name_updates);
	}
	LOG_DBG("Set endpoint name in database[%d]: %d", idx, r);
}

static void gateway_obj_deleted_callback(int idx, void *data_ptr)
{
	ARG_UNUSED(data_ptr);

	if (valid_index(idx)) {
		mb.table_full = false;
	}
}

#if defined(CONFIG_LCZ_MQTT_BLE_LOG_LEVEL_DBG)
static const char *get_name(int idx)
{
	static char name[SENSOR_NAME_MAX_SIZE];
	int r;

	memset(name, 0, sizeof(name));
	r = lcz_lwm2m_gw_obj_get_endpoint_name(idx, name, SENSOR_NAME_MAX_STR_LEN);
	if (r < 0) {
		return "?";
	} else {
		return name;
	}
}
#endif

static void mqtt_ack_callback(int status)
{
	if (status < 0 && attr_get_bool(ATTR_ID_mqtt_ble_enable)) {
		LOG_ERR("MQTT Publish (ack) error: %d", status);
	} else {
		LOG_INF("MQTT Ack id: %d", status);
	}

	flush_ad_list();

	k_sem_give(&mb.ad_list.sem);
}

static void mqtt_connect_callback(int status)
{
	mb.mqtt_connected = true;
}

static void mqtt_disconnect_callback(int status)
{
	mb.mqtt_connected = false;
}
