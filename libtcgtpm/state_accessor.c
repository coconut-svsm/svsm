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
        default:
            /* Unknown section — skip */
            break;
        }
    }

    return 0;
}
