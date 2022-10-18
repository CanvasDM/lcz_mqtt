/**
 * @file nrf-config-user.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __NRF_CONFIG_USER_LCZ_MQTT_H__
#define __NRF_CONFIG_USER_LCZ_MQTT_H__

/* Required for MQTT connection with Azure */
#ifdef MBEDTLS_MPI_MAX_SIZE
#if MBEDTLS_MPI_MAX_SIZE < 512
#undef MBEDTLS_MPI_MAX_SIZE
#define MBEDTLS_MPI_MAX_SIZE 512
#endif
#else
#define MBEDTLS_MPI_MAX_SIZE 512
#endif

#endif /* __NRF_CONFIG_USER_LCZ_MQTT_H__ */
