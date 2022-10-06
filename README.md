# Laird Connectivity Zephyr MQTT Client

Application wrapper for built-in Zephyr MQTT library.

## MQTT BLE Sensor Module

Forwards advertisement data from Laird Connectivity sensors to MQTT broker.  Requires LwM2M Device Management to manage list of allowed devices.

## Shadow Parser Module

Uses JSMN and a linked list to allow multiple application modules (agents) to process subscription data.

### Shadow Parser Flags AWS Module

Parses subscription topic once for use by shadow parsing agents. This working example is for the original Pinnacle AWS Demo.
