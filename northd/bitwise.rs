/*
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

use ddlog_std::option2std;

pub fn u8_next_power_of_two(x: &u8) -> ddlog_std::Option<u8> {
    option2std(x.checked_next_power_of_two())
}
pub fn u16_next_power_of_two(x: &u16) -> ddlog_std::Option<u16> {
    option2std(x.checked_next_power_of_two())
}
pub fn u32_next_power_of_two(x: &u32) -> ddlog_std::Option<u32> {
    option2std(x.checked_next_power_of_two())
}
pub fn u64_next_power_of_two(x: &u64) -> ddlog_std::Option<u64> {
    option2std(x.checked_next_power_of_two())
}
pub fn u128_next_power_of_two(x: &u128) -> ddlog_std::Option<u128> {
    option2std(x.checked_next_power_of_two())
}

// Rust has wrapping_next_power_of_two() in nightly.  We implement it
// ourselves to avoid the dependency.
pub fn u8_wrapping_next_power_of_two(x: &u8) -> u8 {
    x.checked_next_power_of_two().unwrap_or(0)
}
pub fn u16_wrapping_next_power_of_two(x: &u16) -> u16 {
    x.checked_next_power_of_two().unwrap_or(0)
}
pub fn u32_wrapping_next_power_of_two(x: &u32) -> u32 {
    x.checked_next_power_of_two().unwrap_or(0)
}
pub fn u64_wrapping_next_power_of_two(x: &u64) -> u64 {
    x.checked_next_power_of_two().unwrap_or(0)
}
pub fn u128_wrapping_next_power_of_two(x: &u128) -> u128 {
    x.checked_next_power_of_two().unwrap_or(0)
}

pub fn u8_count_ones(x: &u8) -> u32 { x.count_ones() }
pub fn u16_count_ones(x: &u16) -> u32 { x.count_ones() }
pub fn u32_count_ones(x: &u32) -> u32 { x.count_ones() }
pub fn u64_count_ones(x: &u64) -> u32 { x.count_ones() }
pub fn u128_count_ones(x: &u128) -> u32 { x.count_ones() }

pub fn u8_count_zeros(x: &u8) -> u32 { x.count_zeros() }
pub fn u16_count_zeros(x: &u16) -> u32 { x.count_zeros() }
pub fn u32_count_zeros(x: &u32) -> u32 { x.count_zeros() }
pub fn u64_count_zeros(x: &u64) -> u32 { x.count_zeros() }
pub fn u128_count_zeros(x: &u128) -> u32 { x.count_zeros() }

pub fn u8_leading_ones(x: &u8) -> u32 { x.leading_ones() }
pub fn u16_leading_ones(x: &u16) -> u32 { x.leading_ones() }
pub fn u32_leading_ones(x: &u32) -> u32 { x.leading_ones() }
pub fn u64_leading_ones(x: &u64) -> u32 { x.leading_ones() }
pub fn u128_leading_ones(x: &u128) -> u32 { x.leading_ones() }

pub fn u8_leading_zeros(x: &u8) -> u32 { x.leading_zeros() }
pub fn u16_leading_zeros(x: &u16) -> u32 { x.leading_zeros() }
pub fn u32_leading_zeros(x: &u32) -> u32 { x.leading_zeros() }
pub fn u64_leading_zeros(x: &u64) -> u32 { x.leading_zeros() }
pub fn u128_leading_zeros(x: &u128) -> u32 { x.leading_zeros() }

pub fn u8_trailing_ones(x: &u8) -> u32 { x.trailing_ones() }
pub fn u16_trailing_ones(x: &u16) -> u32 { x.trailing_ones() }
pub fn u32_trailing_ones(x: &u32) -> u32 { x.trailing_ones() }
pub fn u64_trailing_ones(x: &u64) -> u32 { x.trailing_ones() }
pub fn u128_trailing_ones(x: &u128) -> u32 { x.trailing_ones() }

pub fn u8_trailing_zeros(x: &u8) -> u32 { x.trailing_zeros() }
pub fn u16_trailing_zeros(x: &u16) -> u32 { x.trailing_zeros() }
pub fn u32_trailing_zeros(x: &u32) -> u32 { x.trailing_zeros() }
pub fn u64_trailing_zeros(x: &u64) -> u32 { x.trailing_zeros() }
pub fn u128_trailing_zeros(x: &u128) -> u32 { x.trailing_zeros() }

pub fn u8_reverse_bits(x: &u8) -> u8 { x.reverse_bits() }
pub fn u16_reverse_bits(x: &u16) -> u16 { x.reverse_bits() }
pub fn u32_reverse_bits(x: &u32) -> u32 { x.reverse_bits() }
pub fn u64_reverse_bits(x: &u64) -> u64 { x.reverse_bits() }
pub fn u128_reverse_bits(x: &u128) -> u128 { x.reverse_bits() }

pub fn u8_swap_bytes(x: &u8) -> u8 { x.swap_bytes() }
pub fn u16_swap_bytes(x: &u16) -> u16 { x.swap_bytes() }
pub fn u32_swap_bytes(x: &u32) -> u32 { x.swap_bytes() }
pub fn u64_swap_bytes(x: &u64) -> u64 { x.swap_bytes() }
pub fn u128_swap_bytes(x: &u128) -> u128 { x.swap_bytes() }

pub fn u8_from_be(x: &u8) -> u8 { u8::from_be(*x) }
pub fn u16_from_be(x: &u16) -> u16 { u16::from_be(*x) }
pub fn u32_from_be(x: &u32) -> u32 { u32::from_be(*x) }
pub fn u64_from_be(x: &u64) -> u64 { u64::from_be(*x) }
pub fn u128_from_be(x: &u128) -> u128 { u128::from_be(*x) }

pub fn u8_to_be(x: &u8) -> u8 { x.to_be() }
pub fn u16_to_be(x: &u16) -> u16 { x.to_be() }
pub fn u32_to_be(x: &u32) -> u32 { x.to_be() }
pub fn u64_to_be(x: &u64) -> u64 { x.to_be() }
pub fn u128_to_be(x: &u128) -> u128 { x.to_be() }

pub fn u8_from_le(x: &u8) -> u8 { u8::from_le(*x) }
pub fn u16_from_le(x: &u16) -> u16 { u16::from_le(*x) }
pub fn u32_from_le(x: &u32) -> u32 { u32::from_le(*x) }
pub fn u64_from_le(x: &u64) -> u64 { u64::from_le(*x) }
pub fn u128_from_le(x: &u128) -> u128 { u128::from_le(*x) }

pub fn u8_to_le(x: &u8) -> u8 { x.to_le() }
pub fn u16_to_le(x: &u16) -> u16 { x.to_le() }
pub fn u32_to_le(x: &u32) -> u32 { x.to_le() }
pub fn u64_to_le(x: &u64) -> u64 { x.to_le() }
pub fn u128_to_le(x: &u128) -> u128 { x.to_le() }

pub fn u8_rotate_left(x: &u8, n: &u32) -> u8 { x.rotate_left(*n) }
pub fn u16_rotate_left(x: &u16, n: &u32) -> u16 { x.rotate_left(*n) }
pub fn u32_rotate_left(x: &u32, n: &u32) -> u32 { x.rotate_left(*n) }
pub fn u64_rotate_left(x: &u64, n: &u32) -> u64 { x.rotate_left(*n) }
pub fn u128_rotate_left(x: &u128, n: &u32) -> u128 { x.rotate_left(*n) }

pub fn u8_rotate_right(x: &u8, n: &u32) -> u8 { x.rotate_right(*n) }
pub fn u16_rotate_right(x: &u16, n: &u32) -> u16 { x.rotate_right(*n) }
pub fn u32_rotate_right(x: &u32, n: &u32) -> u32 { x.rotate_right(*n) }
pub fn u64_rotate_right(x: &u64, n: &u32) -> u64 { x.rotate_right(*n) }
pub fn u128_rotate_right(x: &u128, n: &u32) -> u128 { x.rotate_right(*n) }
