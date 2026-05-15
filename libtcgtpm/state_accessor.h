/* SPDX-License-Identifier: MIT
 *
 * TPM internal state accessors for libtcgtpm.
 *
 * Exposes getter/setter functions for the TPM 2.0 Reference Implementation
 * internal global state variables (gp, gc, gr, go). Useful for callers that
 * need to dump or restore the persistent vTPM state (for example, when
 * relocating, snapshotting, or sealing the state to an external root).
 *
 * Integration into the libtcgtpm build:
 *   1. Place this file and state_accessor.c under libtcgtpm/.
 *   2. Add state_accessor.o to the Makefile OBJS list.
 *   3. Add the accessor symbols to the bindgen allowlist in build.rs.
 *
 * A command-based alternative (TPM2_NV_Read, TPM2_ContextSave,
 * TPM2_GetCapability) is specification-compliant but cannot retrieve
 * auth values and seeds, so it is more limited than the direct accessors.
 */

#ifndef STATE_ACCESSOR_H
#define STATE_ACCESSOR_H

#include <stdint.h>
#include <stddef.h>

/* --- Persistent Data (gp) --- */

/* Copy Endorsement Primary Seed (32 bytes) */
void get_ep_seed(uint8_t *out);
void set_ep_seed(const uint8_t *in);

/* Copy Storage Primary Seed (32 bytes) — the SRK seed */
void get_sp_seed(uint8_t *out);
void set_sp_seed(const uint8_t *in);

/* Copy Platform Primary Seed (32 bytes) */
void get_pp_seed(uint8_t *out);
void set_pp_seed(const uint8_t *in);

/* Copy Owner hierarchy auth value (variable, header(2B) + data) */
size_t get_owner_auth(uint8_t *out_buf, size_t buf_size);
void   set_owner_auth(const uint8_t *in, size_t len);

/* Copy Endorsement hierarchy auth value */
size_t get_endorsement_auth(uint8_t *out_buf, size_t buf_size);
void   set_endorsement_auth(const uint8_t *in, size_t len);

/* Copy Lockout auth value */
size_t get_lockout_auth(uint8_t *out_buf, size_t buf_size);
void   set_lockout_auth(const uint8_t *in, size_t len);

/* Total reset counter (u64) — monotonic across TPM lifetime */
uint64_t get_total_reset_count(void);
void     set_total_reset_count(uint64_t val);

/* Reset counter (u32) — reset by TPM2_Clear */
uint32_t get_reset_count(void);
void     set_reset_count(uint32_t val);

/* --- State Clear Data (gc) --- */

/* Copy PCR save area: per-algorithm bank of 24 static PCRs.
 * Returns number of bytes written. */
size_t get_pcr_save(uint8_t *out_buf, size_t buf_size);
void   set_pcr_save(const uint8_t *in, size_t len);

/* Copy platform auth value */
size_t get_platform_auth(uint8_t *out_buf, size_t buf_size);
void   set_platform_auth(const uint8_t *in, size_t len);

/* --- State Reset Data (gr) --- */

uint32_t get_clear_count(void);
void     set_clear_count(uint32_t val);

uint64_t get_object_context_id(void);
void     set_object_context_id(uint64_t val);

/* --- Bulk serialization helpers --- */

/* Serialize all seal-relevant state into a flat buffer.
 * Layout: [4B total_size] [section...]
 * Each section: [1B section_id] [4B len] [data]
 * Section IDs:
 *   0x01 = EPSeed (32B)
 *   0x02 = SPSeed (32B)
 *   0x03 = PPSeed (32B)
 *   0x04 = ownerAuth
 *   0x05 = endorsementAuth
 *   0x06 = lockoutAuth
 *   0x07 = platformAuth
 *   0x08 = PCR save
 *   0x10 = totalResetCount (8B)
 *   0x11 = resetCount (4B)
 *   0x12 = clearCount (4B)
 *
 * Returns: number of bytes written, or 0 on buffer too small. */
size_t serialize_vtpm_state(uint8_t *out_buf, size_t buf_size);

/* Deserialize state back into TPM globals.
 * Returns: 0 on success, nonzero on error. */
int deserialize_vtpm_state(const uint8_t *in, size_t len);

#endif /* STATE_ACCESSOR_H */
