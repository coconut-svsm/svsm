/* SPDX-License-Identifier: MIT
 *
 * TPM internal state accessor — implementation.
 *
 * Provides getter/setter functions that directly read/write the TPM 2.0
 * Reference Implementation internal global state variables (gp, gc, gr).
 */

#include "Tpm.h"

#include <string.h>

/* ============================================================
 * Persistent Data (gp) — Seed Accessors
 * ============================================================ */

void get_ep_seed(uint8_t *out)
{
    memcpy(out, gp.EPSeed.t.buffer, sizeof(gp.EPSeed.t.buffer));
}

void set_ep_seed(const uint8_t *in)
{
    memcpy(gp.EPSeed.t.buffer, in, sizeof(gp.EPSeed.t.buffer));
    gp.EPSeed.t.size = sizeof(gp.EPSeed.t.buffer);
}

void get_sp_seed(uint8_t *out)
{
    memcpy(out, gp.SPSeed.t.buffer, sizeof(gp.SPSeed.t.buffer));
}

void set_sp_seed(const uint8_t *in)
{
    memcpy(gp.SPSeed.t.buffer, in, sizeof(gp.SPSeed.t.buffer));
    gp.SPSeed.t.size = sizeof(gp.SPSeed.t.buffer);
}

void get_pp_seed(uint8_t *out)
{
    memcpy(out, gp.PPSeed.t.buffer, sizeof(gp.PPSeed.t.buffer));
}

void set_pp_seed(const uint8_t *in)
{
    memcpy(gp.PPSeed.t.buffer, in, sizeof(gp.PPSeed.t.buffer));
    gp.PPSeed.t.size = sizeof(gp.PPSeed.t.buffer);
}

/* ============================================================
 * Persistent Data (gp) — Auth Value Accessors
 * ============================================================ */

size_t get_owner_auth(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = gp.ownerAuth.t.size;
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, gp.ownerAuth.t.buffer, copy_len);
    return copy_len;
}

void set_owner_auth(const uint8_t *in, size_t len)
{
    if (len > sizeof(gp.ownerAuth.t.buffer)) len = sizeof(gp.ownerAuth.t.buffer);
    memcpy(gp.ownerAuth.t.buffer, in, len);
    gp.ownerAuth.t.size = (UINT16)len;
}

size_t get_endorsement_auth(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = gp.endorsementAuth.t.size;
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, gp.endorsementAuth.t.buffer, copy_len);
    return copy_len;
}

void set_endorsement_auth(const uint8_t *in, size_t len)
{
    if (len > sizeof(gp.endorsementAuth.t.buffer)) len = sizeof(gp.endorsementAuth.t.buffer);
    memcpy(gp.endorsementAuth.t.buffer, in, len);
    gp.endorsementAuth.t.size = (UINT16)len;
}

size_t get_lockout_auth(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = gp.lockoutAuth.t.size;
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, gp.lockoutAuth.t.buffer, copy_len);
    return copy_len;
}

void set_lockout_auth(const uint8_t *in, size_t len)
{
    if (len > sizeof(gp.lockoutAuth.t.buffer)) len = sizeof(gp.lockoutAuth.t.buffer);
    memcpy(gp.lockoutAuth.t.buffer, in, len);
    gp.lockoutAuth.t.size = (UINT16)len;
}

/* ============================================================
 * Persistent Data (gp) — Counter Accessors
 * ============================================================ */

uint64_t get_total_reset_count(void)
{
    return gp.totalResetCount;
}

void set_total_reset_count(uint64_t val)
{
    gp.totalResetCount = val;
}

uint32_t get_reset_count(void)
{
    return gp.resetCount;
}

void set_reset_count(uint32_t val)
{
    gp.resetCount = val;
}

/* ============================================================
 * State Clear Data (gc) — PCR Save
 * ============================================================ */

size_t get_pcr_save(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = sizeof(gc.pcrSave);
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, &gc.pcrSave, copy_len);
    return copy_len;
}

void set_pcr_save(const uint8_t *in, size_t len)
{
    size_t copy_len = sizeof(gc.pcrSave);
    if (len < copy_len) copy_len = len;
    memcpy(&gc.pcrSave, in, copy_len);
}

/* ============================================================
 * State Clear Data (gc) — Platform Auth
 * ============================================================ */

size_t get_platform_auth(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = gc.platformAuth.t.size;
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, gc.platformAuth.t.buffer, copy_len);
    return copy_len;
}

void set_platform_auth(const uint8_t *in, size_t len)
{
    if (len > sizeof(gc.platformAuth.t.buffer)) len = sizeof(gc.platformAuth.t.buffer);
    memcpy(gc.platformAuth.t.buffer, in, len);
    gc.platformAuth.t.size = (UINT16)len;
}

/* ============================================================
 * State Reset Data (gr) — Counter Accessors
 * ============================================================ */

uint32_t get_clear_count(void)
{
    return gr.clearCount;
}

void set_clear_count(uint32_t val)
{
    gr.clearCount = val;
}

uint64_t get_object_context_id(void)
{
    return gr.objectContextID;
}

void set_object_context_id(uint64_t val)
{
    gr.objectContextID = val;
}

/* ============================================================
 * Persistent Data (gp) — Dictionary Attack tracking
 * ============================================================ */

uint32_t get_failed_tries(void)            { return gp.failedTries; }
void     set_failed_tries(uint32_t val)    { gp.failedTries = val; }
uint32_t get_max_tries(void)               { return gp.maxTries; }
void     set_max_tries(uint32_t val)       { gp.maxTries = val; }
uint32_t get_recovery_time(void)           { return gp.recoveryTime; }
void     set_recovery_time(uint32_t val)   { gp.recoveryTime = val; }
uint32_t get_lockout_recovery(void)        { return gp.lockoutRecovery; }
void     set_lockout_recovery(uint32_t val){ gp.lockoutRecovery = val; }

uint8_t get_lockout_auth_enabled(void)
{
    return gp.lockOutAuthEnabled ? 1 : 0;
}

void set_lockout_auth_enabled(uint8_t val)
{
    gp.lockOutAuthEnabled = val ? TRUE : FALSE;
}

/* ============================================================
 * Persistent Data (gp) — Orderly shutdown state
 * ============================================================ */

uint16_t get_orderly_state(void)
{
    return (uint16_t)gp.orderlyState;
}

void set_orderly_state(uint16_t val)
{
    gp.orderlyState = (TPM_SU)val;
}

/* ============================================================
 * Persistent Data (gp) — PCR allocation
 * ============================================================ */

size_t get_pcr_allocated(uint8_t *out_buf, size_t buf_size)
{
    size_t copy_len = sizeof(gp.pcrAllocated);
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(out_buf, &gp.pcrAllocated, copy_len);
    return copy_len;
}

void set_pcr_allocated(const uint8_t *in, size_t len)
{
    size_t copy_len = sizeof(gp.pcrAllocated);
    if (len < copy_len) copy_len = len;
    memcpy(&gp.pcrAllocated, in, copy_len);
}

/* ============================================================
 * Platform NV memory blob (Tier-B)
 * ============================================================
 *
 * The simulator's `s_NV[NV_MEMORY_SIZE]` flat buffer holds, in order:
 *   [0 .. sizeof(gp))                       PERSISTENT_DATA (mirror of gp)
 *   [sizeof(gp) .. NV_USER_DYNAMIC)         STATE_RESET / STATE_CLEAR /
 *                                           index-orderly RAM mirror
 *   [NV_USER_DYNAMIC .. NV_MEMORY_SIZE)     dynamic area: user NV indices
 *                                           and evict objects + list end
 *
 * NV-index lookup (`NvNext` in NvDynamic.c) walks this byte layout directly
 * via `_plat__NvMemoryRead`, so there is no separate in-memory index cache to
 * rebuild — restoring the 16 KB bytes is sufficient for `tpm2_nvread` of a
 * user index to resolve after cold-boot Recover.
 */

extern int  _plat__NvMemoryRead(unsigned int startOffset, unsigned int size, void *data);
extern int  _plat__NvMemoryWrite(unsigned int startOffset, unsigned int size, void *data);
extern void NvReadPersistent(void);

#define STATE_NV_BACKUP_SIZE 16384u  /* matches TpmProfile_Misc.h NV_MEMORY_SIZE */

size_t get_nv_blob(uint8_t *out_buf, size_t buf_size)
{
    if (buf_size < STATE_NV_BACKUP_SIZE) return 0;
    /* Force RAM gp into s_NV[NV_PERSISTENT_DATA=0] so the dumped blob
     * reflects the latest in-memory persistent state, not the last NvCommit. */
    _plat__NvMemoryWrite(0, (unsigned int)sizeof(gp), &gp);
    _plat__NvMemoryRead(0, STATE_NV_BACKUP_SIZE, out_buf);
    return STATE_NV_BACKUP_SIZE;
}

void set_nv_blob(const uint8_t *in, size_t len)
{
    unsigned int n = (len < STATE_NV_BACKUP_SIZE) ? (unsigned int)len : STATE_NV_BACKUP_SIZE;
    /* Cast away const for the platform API; it does a memcpy and never writes
     * through the pointer. */
    _plat__NvMemoryWrite(0, n, (void *)(uintptr_t)in);
    /* Sync the freshly-written s_NV[NV_PERSISTENT_DATA] back into RAM gp.
     * Subsequent 0x01-0x19 sections will overlay individual fields on top. */
    NvReadPersistent();
}

/* ============================================================
 * Bulk Serialization
 * ============================================================
 *
 * Layout: [4B total_size] [section...]
 * Each section: [1B section_id] [4B len] [data]
 */

/* Helper: write a section into buf at offset. Returns bytes written, 0 on overflow. */
static size_t write_section(uint8_t *buf, size_t buf_size, size_t offset,
                            uint8_t section_id, const uint8_t *data, size_t data_len)
{
    size_t needed = offset + 5 + data_len;
    if (needed > buf_size) return 0;

    buf[offset]     = section_id;
    buf[offset + 1] = (uint8_t)(data_len & 0xFF);
    buf[offset + 2] = (uint8_t)((data_len >> 8) & 0xFF);
    buf[offset + 3] = (uint8_t)((data_len >> 16) & 0xFF);
    buf[offset + 4] = (uint8_t)((data_len >> 24) & 0xFF);
    memcpy(buf + offset + 5, data, data_len);

    return 5 + data_len;
}

/* Helper: write a fixed-size value as a section */
static size_t write_section_val(uint8_t *buf, size_t buf_size, size_t offset,
                                uint8_t section_id, const uint8_t *val, size_t val_len)
{
    return write_section(buf, buf_size, offset, section_id, val, val_len);
}

size_t serialize_vtpm_state(uint8_t *out_buf, size_t buf_size)
{
    size_t offset = 4; /* reserve 4 bytes for total size */
    size_t written;

    /* 0x1A: platform NV blob (16384B).
     *
     * IMPORTANT: emitted FIRST so the deserializer applies it before the
     * 0x01-0x19 setters. Otherwise `NvReadPersistent()` inside `set_nv_blob`
     * would clobber the previously-restored RAM gp fields.
     *
     * Dumped directly into out_buf to avoid a 16 KB intermediate stack buffer
     * in the SVSM kernel context (where stack is more constrained than in a
     * userspace swtpm process). */
    {
        size_t needed = offset + 5 + STATE_NV_BACKUP_SIZE;
        if (needed > buf_size) return 0;
        /* Force RAM gp into s_NV[NV_PERSISTENT_DATA=0] so the dumped blob
         * reflects the latest in-memory persistent state. */
        _plat__NvMemoryWrite(0, (unsigned int)sizeof(gp), &gp);
        out_buf[offset]     = 0x1A;
        out_buf[offset + 1] = (uint8_t)(STATE_NV_BACKUP_SIZE & 0xFFu);
        out_buf[offset + 2] = (uint8_t)((STATE_NV_BACKUP_SIZE >> 8) & 0xFFu);
        out_buf[offset + 3] = (uint8_t)((STATE_NV_BACKUP_SIZE >> 16) & 0xFFu);
        out_buf[offset + 4] = (uint8_t)((STATE_NV_BACKUP_SIZE >> 24) & 0xFFu);
        _plat__NvMemoryRead(0, STATE_NV_BACKUP_SIZE, out_buf + offset + 5);
        offset += 5 + STATE_NV_BACKUP_SIZE;
    }

    /* 0x01: EP Seed (32B) */
    written = write_section_val(out_buf, buf_size, offset, 0x01,
                                gp.EPSeed.t.buffer, sizeof(gp.EPSeed.t.buffer));
    if (!written) return 0;
    offset += written;

    /* 0x02: SP Seed (32B) */
    written = write_section_val(out_buf, buf_size, offset, 0x02,
                                gp.SPSeed.t.buffer, sizeof(gp.SPSeed.t.buffer));
    if (!written) return 0;
    offset += written;

    /* 0x03: PP Seed (32B) */
    written = write_section_val(out_buf, buf_size, offset, 0x03,
                                gp.PPSeed.t.buffer, sizeof(gp.PPSeed.t.buffer));
    if (!written) return 0;
    offset += written;

    /* 0x04: ownerAuth */
    written = write_section(out_buf, buf_size, offset, 0x04,
                            gp.ownerAuth.t.buffer, gp.ownerAuth.t.size);
    if (!written) return 0;
    offset += written;

    /* 0x05: endorsementAuth */
    written = write_section(out_buf, buf_size, offset, 0x05,
                            gp.endorsementAuth.t.buffer, gp.endorsementAuth.t.size);
    if (!written) return 0;
    offset += written;

    /* 0x06: lockoutAuth */
    written = write_section(out_buf, buf_size, offset, 0x06,
                            gp.lockoutAuth.t.buffer, gp.lockoutAuth.t.size);
    if (!written) return 0;
    offset += written;

    /* 0x07: platformAuth */
    written = write_section(out_buf, buf_size, offset, 0x07,
                            gc.platformAuth.t.buffer, gc.platformAuth.t.size);
    if (!written) return 0;
    offset += written;

    /* 0x08: PCR save area */
    written = write_section(out_buf, buf_size, offset, 0x08,
                            (const uint8_t *)&gc.pcrSave, sizeof(gc.pcrSave));
    if (!written) return 0;
    offset += written;

    /* 0x10: totalResetCount (8B) */
    {
        uint8_t trc[8];
        trc[0] = (uint8_t)(gp.totalResetCount & 0xFF);
        trc[1] = (uint8_t)((gp.totalResetCount >> 8) & 0xFF);
        trc[2] = (uint8_t)((gp.totalResetCount >> 16) & 0xFF);
        trc[3] = (uint8_t)((gp.totalResetCount >> 24) & 0xFF);
        trc[4] = (uint8_t)((gp.totalResetCount >> 32) & 0xFF);
        trc[5] = (uint8_t)((gp.totalResetCount >> 40) & 0xFF);
        trc[6] = (uint8_t)((gp.totalResetCount >> 48) & 0xFF);
        trc[7] = (uint8_t)((gp.totalResetCount >> 56) & 0xFF);
        written = write_section_val(out_buf, buf_size, offset, 0x10, trc, 8);
        if (!written) return 0;
        offset += written;
    }

    /* 0x11: resetCount (4B) */
    {
        uint8_t rc[4];
        rc[0] = (uint8_t)(gp.resetCount & 0xFF);
        rc[1] = (uint8_t)((gp.resetCount >> 8) & 0xFF);
        rc[2] = (uint8_t)((gp.resetCount >> 16) & 0xFF);
        rc[3] = (uint8_t)((gp.resetCount >> 24) & 0xFF);
        written = write_section_val(out_buf, buf_size, offset, 0x11, rc, 4);
        if (!written) return 0;
        offset += written;
    }

    /* 0x12: clearCount (4B) */
    {
        uint8_t cc[4];
        cc[0] = (uint8_t)(gr.clearCount & 0xFF);
        cc[1] = (uint8_t)((gr.clearCount >> 8) & 0xFF);
        cc[2] = (uint8_t)((gr.clearCount >> 16) & 0xFF);
        cc[3] = (uint8_t)((gr.clearCount >> 24) & 0xFF);
        written = write_section_val(out_buf, buf_size, offset, 0x12, cc, 4);
        if (!written) return 0;
        offset += written;
    }

    /* 0x13..0x16: DA UINT32 fields (failedTries, maxTries, recoveryTime, lockoutRecovery) */
    {
        const uint32_t da_vals[4] = {
            gp.failedTries,
            gp.maxTries,
            gp.recoveryTime,
            gp.lockoutRecovery,
        };
        const uint8_t  da_ids[4] = { 0x13, 0x14, 0x15, 0x16 };
        for (int i = 0; i < 4; ++i) {
            uint8_t v[4];
            v[0] = (uint8_t)(da_vals[i] & 0xFF);
            v[1] = (uint8_t)((da_vals[i] >> 8) & 0xFF);
            v[2] = (uint8_t)((da_vals[i] >> 16) & 0xFF);
            v[3] = (uint8_t)((da_vals[i] >> 24) & 0xFF);
            written = write_section_val(out_buf, buf_size, offset, da_ids[i], v, 4);
            if (!written) return 0;
            offset += written;
        }
    }

    /* 0x17: lockOutAuthEnabled (1B) */
    {
        uint8_t lae = gp.lockOutAuthEnabled ? 1 : 0;
        written = write_section_val(out_buf, buf_size, offset, 0x17, &lae, 1);
        if (!written) return 0;
        offset += written;
    }

    /* 0x18: orderlyState (2B, TPM_SU = UINT16) */
    {
        uint8_t os[2];
        uint16_t v = (uint16_t)gp.orderlyState;
        os[0] = (uint8_t)(v & 0xFF);
        os[1] = (uint8_t)((v >> 8) & 0xFF);
        written = write_section_val(out_buf, buf_size, offset, 0x18, os, 2);
        if (!written) return 0;
        offset += written;
    }

    /* 0x19: pcrAllocated (TPML_PCR_SELECTION, raw struct dump) */
    written = write_section(out_buf, buf_size, offset, 0x19,
                            (const uint8_t *)&gp.pcrAllocated,
                            sizeof(gp.pcrAllocated));
    if (!written) return 0;
    offset += written;

    /* Write total size at the beginning */
    out_buf[0] = (uint8_t)(offset & 0xFF);
    out_buf[1] = (uint8_t)((offset >> 8) & 0xFF);
    out_buf[2] = (uint8_t)((offset >> 16) & 0xFF);
    out_buf[3] = (uint8_t)((offset >> 24) & 0xFF);

    return offset;
}

int deserialize_vtpm_state(const uint8_t *in, size_t len)
{
    if (len < 4) return -1;

    uint32_t total_size = (uint32_t)in[0]
                        | ((uint32_t)in[1] << 8)
                        | ((uint32_t)in[2] << 16)
                        | ((uint32_t)in[3] << 24);
    if (total_size > len) return -2;

    size_t offset = 4;
    while (offset + 5 <= total_size) {
        uint8_t section_id = in[offset];
        uint32_t data_len = (uint32_t)in[offset + 1]
                          | ((uint32_t)in[offset + 2] << 8)
                          | ((uint32_t)in[offset + 3] << 16)
                          | ((uint32_t)in[offset + 4] << 24);
        offset += 5;

        if (offset + data_len > total_size) return -3;

        const uint8_t *data = in + offset;
        offset += data_len;

        switch (section_id) {
        case 0x01: /* EPSeed */
            if (data_len > sizeof(gp.EPSeed.t.buffer)) return -4;
            memcpy(gp.EPSeed.t.buffer, data, data_len);
            gp.EPSeed.t.size = sizeof(gp.EPSeed.t.buffer);
            break;
        case 0x02: /* SPSeed */
            if (data_len > sizeof(gp.SPSeed.t.buffer)) return -4;
            memcpy(gp.SPSeed.t.buffer, data, data_len);
            gp.SPSeed.t.size = sizeof(gp.SPSeed.t.buffer);
            break;
        case 0x03: /* PPSeed */
            if (data_len > sizeof(gp.PPSeed.t.buffer)) return -4;
            memcpy(gp.PPSeed.t.buffer, data, data_len);
            gp.PPSeed.t.size = sizeof(gp.PPSeed.t.buffer);
            break;
        case 0x04: /* ownerAuth */
            if (data_len > sizeof(gp.ownerAuth.t.buffer)) return -4;
            memcpy(gp.ownerAuth.t.buffer, data, data_len);
            gp.ownerAuth.t.size = (UINT16)data_len;
            break;
        case 0x05: /* endorsementAuth */
            if (data_len > sizeof(gp.endorsementAuth.t.buffer)) return -4;
            memcpy(gp.endorsementAuth.t.buffer, data, data_len);
            gp.endorsementAuth.t.size = (UINT16)data_len;
            break;
        case 0x06: /* lockoutAuth */
            if (data_len > sizeof(gp.lockoutAuth.t.buffer)) return -4;
            memcpy(gp.lockoutAuth.t.buffer, data, data_len);
            gp.lockoutAuth.t.size = (UINT16)data_len;
            break;
        case 0x07: /* platformAuth */
            if (data_len > sizeof(gc.platformAuth.t.buffer)) return -4;
            memcpy(gc.platformAuth.t.buffer, data, data_len);
            gc.platformAuth.t.size = (UINT16)data_len;
            break;
        case 0x08: /* PCR save */
            if (data_len > sizeof(gc.pcrSave)) return -4;
            memcpy(&gc.pcrSave, data, data_len);
            break;
        case 0x10: /* totalResetCount */
            if (data_len < 8) return -4;
            gp.totalResetCount = (uint64_t)data[0]
                               | ((uint64_t)data[1] << 8)
                               | ((uint64_t)data[2] << 16)
                               | ((uint64_t)data[3] << 24)
                               | ((uint64_t)data[4] << 32)
                               | ((uint64_t)data[5] << 40)
                               | ((uint64_t)data[6] << 48)
                               | ((uint64_t)data[7] << 56);
            break;
        case 0x11: /* resetCount */
            if (data_len < 4) return -4;
            gp.resetCount = (uint32_t)data[0]
                          | ((uint32_t)data[1] << 8)
                          | ((uint32_t)data[2] << 16)
                          | ((uint32_t)data[3] << 24);
            break;
        case 0x12: /* clearCount */
            if (data_len < 4) return -4;
            gr.clearCount = (uint32_t)data[0]
                          | ((uint32_t)data[1] << 8)
                          | ((uint32_t)data[2] << 16)
                          | ((uint32_t)data[3] << 24);
            break;
        case 0x13: /* failedTries */
            if (data_len < 4) return -4;
            gp.failedTries = (uint32_t)data[0]
                           | ((uint32_t)data[1] << 8)
                           | ((uint32_t)data[2] << 16)
                           | ((uint32_t)data[3] << 24);
            break;
        case 0x14: /* maxTries */
            if (data_len < 4) return -4;
            gp.maxTries = (uint32_t)data[0]
                        | ((uint32_t)data[1] << 8)
                        | ((uint32_t)data[2] << 16)
                        | ((uint32_t)data[3] << 24);
            break;
        case 0x15: /* recoveryTime */
            if (data_len < 4) return -4;
            gp.recoveryTime = (uint32_t)data[0]
                            | ((uint32_t)data[1] << 8)
                            | ((uint32_t)data[2] << 16)
                            | ((uint32_t)data[3] << 24);
            break;
        case 0x16: /* lockoutRecovery */
            if (data_len < 4) return -4;
            gp.lockoutRecovery = (uint32_t)data[0]
                               | ((uint32_t)data[1] << 8)
                               | ((uint32_t)data[2] << 16)
                               | ((uint32_t)data[3] << 24);
            break;
        case 0x17: /* lockOutAuthEnabled */
            if (data_len < 1) return -4;
            gp.lockOutAuthEnabled = data[0] ? TRUE : FALSE;
            break;
        case 0x18: /* orderlyState (TPM_SU = UINT16) */
            if (data_len < 2) return -4;
            gp.orderlyState = (TPM_SU)((uint16_t)data[0]
                                     | ((uint16_t)data[1] << 8));
            break;
        case 0x19: /* pcrAllocated (TPML_PCR_SELECTION) */
            if (data_len > sizeof(gp.pcrAllocated)) return -4;
            memcpy(&gp.pcrAllocated, data, data_len);
            break;
        case 0x1A: /* platform NV blob (16384B s_NV[]) — Tier-B */
            if (data_len != STATE_NV_BACKUP_SIZE) return -4;
            /* set_nv_blob() writes s_NV[] then re-syncs RAM gp from
             * s_NV[NV_PERSISTENT_DATA=0]. Subsequent 0x01-0x19 cases will
             * overwrite individual gp fields with the per-section copies. */
            set_nv_blob(data, data_len);
            break;
        default:
            /* Unknown section — skip */
            break;
        }
    }

    return 0;
}
