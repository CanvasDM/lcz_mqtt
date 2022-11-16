/**
 * @file lcz_mqtt_mbedtls_config.h.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#ifndef __LCZ_MQTT_MBEDTLS_CONFIG_H__
#define __LCZ_MQTT_MBEDTLS_CONFIG_H__

/* Required for MQTT connection with Azure */
#ifdef MBEDTLS_MPI_MAX_SIZE
#if MBEDTLS_MPI_MAX_SIZE < 512
#undef MBEDTLS_MPI_MAX_SIZE
#define MBEDTLS_MPI_MAX_SIZE 512
#endif
#else
#define MBEDTLS_MPI_MAX_SIZE 512
#endif

#endif /* __LCZ_MQTT_MBEDTLS_CONFIG_H__ */
