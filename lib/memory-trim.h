/*
 * Copyright (c) 2022, Red Hat, Inc.
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

#ifndef MEMORY_TRIM_H
#define MEMORY_TRIM_H 1

#include <stdbool.h>
#include <stdint.h>

struct memory_trimmer;

struct memory_trimmer *memory_trimmer_create(void);
void memory_trimmer_destroy(struct memory_trimmer *);
void memory_trimmer_set(struct memory_trimmer *, uint32_t trim_timeout_ms);
bool memory_trimmer_can_run(struct memory_trimmer *);
void memory_trimmer_wait(struct memory_trimmer *);
void memory_trimmer_trim(struct memory_trimmer *);
void memory_trimmer_record_activity(struct memory_trimmer *);

#endif /* lib/memory-trim.h */
