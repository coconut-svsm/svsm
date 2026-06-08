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

/* --- Persistent Data (gp) — Dictionary Attack tracking ---
 *
 * Without these the post-Recover guest hits TPM_RC_LOCKOUT (0x921) on the
 * first auth-bearing command because the simulator re-initializes DA state
 * to default after deserialize, mismatching the previously-stored
 * hierarchy auth values. */
uint32_t get_failed_tries(void);
void     set_failed_tries(uint32_t val);
uint32_t get_max_tries(void);
void     set_max_tries(uint32_t val);
uint32_t get_recovery_time(void);
void     set_recovery_time(uint32_t val);
uint32_t get_lockout_recovery(void);
void     set_lockout_recovery(uint32_t val);
/* gp.lockOutAuthEnabled is BOOL (int); marshalled as a single byte (0/1). */
uint8_t  get_lockout_auth_enabled(void);
void     set_lockout_auth_enabled(uint8_t val);

/* --- Persistent Data (gp) — Orderly shutdown state ---
 * TPM_SU is a UINT16. Used by Startup to decide between TPM_SU_CLEAR /
 * TPM_SU_STATE branches; if missing, NV reload and PCR alloc behave as if
 * we suffered an unexpected shutdown. */
uint16_t get_orderly_state(void);
void     set_orderly_state(uint16_t val);

/* --- Persistent Data (gp) — PCR allocation ---
 * gp.pcrAllocated is a TPML_PCR_SELECTION (small variable-size struct,
 * ≤ ~130 B). Without it, the simulator forgets which PCR banks (sha1 /
 * sha256 / sha384 / sha512) are active and tpm2_pcrread rejects them as
 * "unsupported bank/algorithm". */
size_t get_pcr_allocated(uint8_t *out_buf, size_t buf_size);
void   set_pcr_allocated(const uint8_t *in, size_t len);

/* --- Platform NV memory blob (Tier-B) ---
 * The TPM Reference Implementation keeps user-defined NV indices and evict
 * objects inside a flat 16 KB `s_NV[]` buffer. Without restoring this buffer
 * across cold boot, `tpm2_nvread 0x1500016` after Recover fails with
 * "handle does not exist" — the simulator scans s_NV at command time, and
 * the freshly-initialized buffer contains no user indices. */
size_t get_nv_blob(uint8_t *out_buf, size_t buf_size);
void   set_nv_blob(const uint8_t *in, size_t len);

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
 *   0x13 = failedTries (4B)          [Tier-A: DA persistence]
 *   0x14 = maxTries (4B)
 *   0x15 = recoveryTime (4B)
 *   0x16 = lockoutRecovery (4B)
 *   0x17 = lockOutAuthEnabled (1B)
 *   0x18 = orderlyState (2B, TPM_SU)
 *   0x19 = pcrAllocated (TPML_PCR_SELECTION, ≤ ~130B)
 *   0x1A = platform NV blob (16384B s_NV[]) [Tier-B: user NV index/evict object
 *          persistence]. MUST be emitted FIRST in the blob so deserialize
 *          applies it before 0x01-0x19 setters overwrite RAM gp fields.
 *
 * Old blobs (without 0x13-0x1A) deserialize fine — unknown sections are
 * skipped, simulator-default values stay in place for those fields.
 *
 * Returns: number of bytes written, or 0 on buffer too small. */
size_t serialize_vtpm_state(uint8_t *out_buf, size_t buf_size);

/* Deserialize state back into TPM globals.
 * Returns: 0 on success, nonzero on error. */
int deserialize_vtpm_state(const uint8_t *in, size_t len);

#endif /* STATE_ACCESSOR_H */
