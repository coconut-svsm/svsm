#ifndef __INCLUDE_TYPES_H
#define __INCLUDE_TYPES_H

/* Segment selectors */
#define	__SVSMLOADER32_CS	0x8
#define	__SVSMLOADER32_DS	0x10
#define __SVSMLOADER64_CS	0x18
#define __SVSMLOADER64_DS	0x20

/* CR0 Bits*/
#define	CR0_PAGING_BIT	31

/* CR4 Bits */
#define CR4_PAE_BIT		5

/* MSR definitions */
#define MSR_EFER	0xc0000080
#define	EFER_LME_BIT	8

#define MSR_GHCB	0xc0010130
#define MSR_SEV_STATUS	0xc0010131

/* GHCB MSR Protocol definitions*/
#define GHCB_MSR_SNP_STATE_CHANGE	0x14


/* Some instructions */
#define PVALIDATE	.byte 0xf2, 0x0f, 0x01, 0xff
#define VMGEXIT		rep; vmmcall

#endif /* __INCLUDE_TYPES_H */
