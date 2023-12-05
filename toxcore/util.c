/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Utilities.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "ccompat.h"

bool is_power_of_2(uint64_t x)
{
    return x != 0 && (x & (~x + 1)) == x;
}

void free_uint8_t_pointer_array(const Memory *mem, uint8_t **ary, size_t n_items)
{
    if (ary == nullptr) {
        return;
    }

    for (size_t i = 0; i < n_items; ++i) {
        if (ary[i] != nullptr) {
            mem_delete(mem, ary[i]);
        }
    }

    mem_delete(mem, ary);
}

uint16_t data_checksum(const uint8_t *data, uint32_t length)
{
    uint8_t checksum[2] = {0};
    uint16_t check;

    for (uint32_t i = 0; i < length; ++i) {
        checksum[i % 2] ^= data[i];
    }

    memcpy(&check, checksum, sizeof(check));
    return check;
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    /* Create queue mutex */
    if (pthread_mutex_init(mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    return 0;
}

bool memeq(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size)
{
    return a_size == b_size && memcmp(a, b, a_size) == 0;
}

int16_t max_s16(int16_t a, int16_t b)
{
    return a > b ? a : b;
}
int32_t max_s32(int32_t a, int32_t b)
{
    return a > b ? a : b;
}
int64_t max_s64(int64_t a, int64_t b)
{
    return a > b ? a : b;
}

int16_t min_s16(int16_t a, int16_t b)
{
    return a < b ? a : b;
}
int32_t min_s32(int32_t a, int32_t b)
{
    return a < b ? a : b;
}
int64_t min_s64(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

uint16_t max_u16(uint16_t a, uint16_t b)
{
    return a > b ? a : b;
}
uint32_t max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}
uint64_t max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

uint16_t min_u16(uint16_t a, uint16_t b)
{
    return a < b ? a : b;
}
uint32_t min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}
uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len)
{
    uint32_t hash = 0;

    for (uint32_t i = 0; i < len; ++i) {
        hash += key[i];
        hash += (uint32_t)((uint64_t)hash << 10);
        hash ^= hash >> 6;
    }

    hash += (uint32_t)((uint64_t)hash << 3);
    hash ^= hash >> 11;
    hash += (uint32_t)((uint64_t)hash << 15);
    return hash;
}

/** generic function to print bytes as String; based on id_to_string() from Messenger.c */
void bytes_to_string(const uint8_t *bytes, size_t bytes_length, char *str, size_t str_length)
{
    if (str_length < (bytes_length * 2 + 1)) {
        snprintf(str, str_length, "Bad buf length");
    }

    for (uint32_t i = 0; i < bytes_length; ++i) {
        snprintf(&str[i * 2], str_length - i * 2, "%02X", bytes[i]);
    }

    str[bytes_length * 2] = '\0';
}
