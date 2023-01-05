// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 chargebyte GmbH
// Copyright (C) 2022 Contributors to EVerest
#ifndef TOOLS_H
#define TOOLS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define max(a,b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b; })

#define min(a,b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; })

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)          (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef ROUND_UP
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#endif

#ifndef ROUND_UP_ELEMENTS
#define ROUND_UP_ELEMENTS(N, S) (((N) + (S) - 1) / (S))
#endif

int generate_random_data(void *dest, size_t dest_len);
unsigned int generate_srand_seed(void);

enum Addr6Type {
	ADDR6_TYPE_UNPSEC = -1,
	ADDR6_TYPE_GLOBAL = 0,
	ADDR6_TYPE_LINKLOCAL = 1,
};
int get_interface_ipv6_address(const char *if_name, enum Addr6Type type, struct sockaddr_in6 *addr);

void set_normalized_timespec(struct timespec *ts, time_t sec, int64_t nsec);
int timespec_compare(const struct timespec *lhs, const struct timespec *rhs);
struct timespec timespec_sub(struct timespec lhs, struct timespec rhs);
struct timespec timespec_add(struct timespec lhs, struct timespec rhs);
void timespec_add_ms(struct timespec *ts, long long msec);
long long timespec_to_ms(struct timespec ts);
long long timespec_to_us(struct timespec ts);
int msleep(int ms);
long long int getmonotonictime(void);

/*!
 * \brief range_check_int32 This function checks if an int32 value is within the given range.
 * \param min is the min value.
 * \param max is the max value.
 * \param value which must be checked.
 * \return Returns \c true if it is within range, otherwise \c false.
 */
bool range_check_int32(int32_t min, int32_t max, int32_t value);

/*!
 * \brief range_check_int64 This function checks if an int64 value is within the given range.
 * \param min is the min value.
 * \param max is the max value.
 * \param value which must be checked.
 * \return Returns \c true if it is within range, otherwise \c false.
 */
bool range_check_int64(int64_t min, int64_t max, int64_t value);

/*!
 * \brief round_down "round" a string representation of a float down to 1 decimal places
 * \param buffer is the float string
 * \param len is the length of the buffer
 */
void round_down(const char *buffer, size_t len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* TOOLS_H */
