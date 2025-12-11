/* Copyright (c) 2021, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H 1

#include <sys/types.h>
#include <netinet/in.h>

#include "openvswitch/types.h"
#include "ovstest.h"

bool test_read_uint_value(struct ovs_cmdl_context *ctx, unsigned int index,
                          const char *descr, unsigned int *result);
bool test_read_uint_hex_value(struct ovs_cmdl_context *ctx, unsigned int index,
                              const char *descr, unsigned int *result);
const char *test_read_value(struct ovs_cmdl_context *ctx, unsigned int index,
                            const char *descr);
bool test_read_ullong_value(struct ovs_cmdl_context *ctx, unsigned int index,
                            const char *descr, unsigned long long int *result);
bool test_read_eth_addr_value(struct ovs_cmdl_context *ctx, unsigned int index,
                              const char *descr, struct eth_addr *result);
bool test_read_ipv6_mapped_value(struct ovs_cmdl_context *ctx,
                                 unsigned int index, const char *descr,
                                 struct in6_addr *result);
bool test_read_ipv6_cidr_mapped_value(struct ovs_cmdl_context *ctx,
                                      unsigned int index, const char *descr,
                                      struct in6_addr *result,
                                      unsigned int *plen);
#endif /* tests/test-utils.h */
