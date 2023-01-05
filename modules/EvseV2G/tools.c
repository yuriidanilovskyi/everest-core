/*
 * Copyright © 2017 I2SE GmbH
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "tools.h"

ssize_t safe_read(int fd, void *buf, size_t count)
{
	for (;;) {
			ssize_t result = read(fd, buf, count);

			if (result >= 0)
					return result;
			else if (errno == EINTR)
					continue;
			else
					return result;
	}
}

int generate_random_data(void *dest, size_t dest_len)
{
	size_t len = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return -1;

	while (len < dest_len) {
		ssize_t rv = safe_read(fd, dest, dest_len);

		if (rv < 0) {
			close(fd);
			return -1;
		}

		len += rv;
	}

	close(fd);
	return 0;
}

unsigned int generate_srand_seed(void)
{
	unsigned int s;

	if (generate_random_data(&s, sizeof(s)) == -1)
		return 42; /* just to _not_ use 1 which is the default value when srand is not used at all */

	return s;
}

int get_interface_ipv6_address(const char *if_name, enum Addr6Type type, struct sockaddr_in6 *addr)
{
	struct ifaddrs *ifaddr, *ifa;
	int rv = -1;

	if (getifaddrs(&ifaddr) == -1)
		return -1;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		if (strcmp(ifa->ifa_name, if_name) != 0)
			continue;

		/* on Linux the scope_id is interface index for link-local addresses */
		switch (type) {
		case ADDR6_TYPE_GLOBAL: /* no link-local address requested */
			if (((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_scope_id != 0)
				continue;
			break;

		case ADDR6_TYPE_LINKLOCAL: /* link-local address requested */
			if (((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_scope_id == 0)
				continue;
			break;

		default: /* any address of the interface requested */
			/* use first found */
			break;
		}

		memcpy(addr, ifa->ifa_addr, sizeof(*addr));

		rv = 0;
		goto out;
	}

out:
	freeifaddrs(ifaddr);
	return rv;
}

#define NSEC_PER_SEC 1000000000L

void set_normalized_timespec(struct timespec *ts, time_t sec, int64_t nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

struct timespec timespec_add(struct timespec lhs, struct timespec rhs)
{
	struct timespec ts_delta;

	set_normalized_timespec(&ts_delta, lhs.tv_sec + rhs.tv_sec, lhs.tv_nsec + rhs.tv_nsec);

	return ts_delta;
}

struct timespec timespec_sub(struct timespec lhs, struct timespec rhs)
{
	struct timespec ts_delta;

	set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec, lhs.tv_nsec - rhs.tv_nsec);

	return ts_delta;
}

void timespec_add_ms(struct timespec *ts, long long msec)
{
	long long sec = msec / 1000;

	set_normalized_timespec(ts, ts->tv_sec + sec, ts->tv_nsec + (msec - sec * 1000) * 1000 * 1000);
}

/*
 * lhs < rhs:  return < 0
 * lhs == rhs: return 0
 * lhs > rhs:  return > 0
 */
int timespec_compare(const struct timespec *lhs, const struct timespec *rhs)
{
	if (lhs->tv_sec < rhs->tv_sec)
		return -1;
	if (lhs->tv_sec > rhs->tv_sec)
		return 1;
	return lhs->tv_nsec - rhs->tv_nsec;
}

long long timespec_to_ms(struct timespec ts)
{
	return ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

long long timespec_to_us(struct timespec ts)
{
	return ((long long)ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
}

int msleep(int ms)
{
	struct timespec req, rem;

	req.tv_sec = ms / 1000;
	req.tv_nsec = (ms % 1000) * (1000 * 1000); /* x ms */

	while ((nanosleep(&req, &rem) == (-1)) && (errno == EINTR)) {
		req = rem;
	}

	return 0;
}

long long int getmonotonictime() {
		struct timespec time;
		clock_gettime(CLOCK_MONOTONIC, &time);
		return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

bool range_check_int32(int32_t min, int32_t max, int32_t value) {
	return ((value < min) || (value > max))? false : true;
}

bool range_check_int64(int64_t min, int64_t max, int64_t value) {
	return ((value < min) || (value > max))? false : true;
}

void round_down(const char *buffer, size_t len) {
	char *p;

	p = strchr(buffer, '.');

	if (!p)
		return;

	if (p - buffer > len - 2)
		return;

	if (*(p + 1) == '\0')
		return;

	*(p + 2) = '\0';
}
