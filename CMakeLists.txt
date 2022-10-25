
if(CONFIG_LCZ_MQTT)

zephyr_include_directories(include)

zephyr_sources(source/lcz_mqtt.c)

zephyr_sources_ifdef(CONFIG_LCZ_MQTT_SHADOW_PARSER
    source/lcz_mqtt_shadow_parser.c
)

zephyr_sources_ifdef(CONFIG_LCZ_MQTT_SHADOW_PARSER_FLAGS_AWS
    source/lcz_mqtt_shadow_parser_flags_aws.c
)

if(CONFIG_LCZ_MQTT_AZURE)
zephyr_include_directories(mbedtls_config)
endif()

endif()