/*
** Definitions for IBM z/Architecture (s390x) CPUs.
** Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
*/

#ifndef _LJ_TARGET_S390X_H
#define _LJ_TARGET_S390X_H

/* -- Registers IDs ------------------------------------------------------- */

#define GPRDEF(_) \
  _(R0) _(R1) _(R2) _(R3) _(R4) _(R5) _(R6) _(R7) \
  _(R8) _(R9) _(R10) _(R11) _(R12) _(R13) _(R14) _(R15)
#define FPRDEF(_) \
  _(F0) _(F1) _(F2) _(F3) \
  _(F4) _(F5) _(F6) _(F7) \
  _(F8) _(F9) _(F10) _(F11) \
  _(F12) _(F13) _(F14) _(F15)
#define VRIDDEF(_)

#define RIDENUM(name)	RID_##name,

enum {
  GPRDEF(RIDENUM)		/* General-purpose registers (GPRs). */
  FPRDEF(RIDENUM)		/* Floating-point registers (FPRs). */
  RID_MAX,
  RID_TMP = RID_R1,

  /* Calling conventions. */
  RID_SP = RID_R15,
  RID_RET = RID_R2,
  RID_RETLO = RID_R2,
  RID_RETHI = RID_R3,
  RID_FPRET = RID_F0,

  /* These definitions must match with the *.dasc file(s): */
  RID_BASE = RID_R13,		/* Interpreter BASE. */
  RID_LPC = RID_R9,		/* Interpreter PC. */
  RID_DISPATCH = RID_R10,	/* Interpreter DISPATCH table. */
  RID_JGL = RID_R11,		/* On-trace: global_State. */

  /* Register ranges [min, max) and number of registers. */
  RID_MIN_GPR = RID_R0,
  RID_MIN_FPR = RID_F0,
  RID_MAX_GPR = RID_MIN_FPR,
  RID_MAX_FPR = RID_MAX,
  RID_NUM_GPR = RID_MAX_GPR - RID_MIN_GPR,
  RID_NUM_FPR = RID_MAX_FPR - RID_MIN_FPR
};

#define RID_NUM_KREF		RID_NUM_GPR
#define RID_MIN_KREF		RID_R0

/* -- Register sets ------------------------------------------------------- */

/* Make use of all registers, except for r0, r1 (tmp), r11 (JGL) and sp. */
#define RSET_FIXED \
  (RID2RSET(RID_R0)|RID2RSET(RID_TMP)|RID2RSET(RID_JGL)|RID2RSET(RID_SP))
#define RSET_GPR	(RSET_RANGE(RID_MIN_GPR, RID_MAX_GPR) - RSET_FIXED)
#define RSET_FPR	RSET_RANGE(RID_MIN_FPR, RID_MAX_FPR)
#define RSET_ALL	(RSET_GPR|RSET_FPR)
#define RSET_INIT	RSET_ALL

#define RSET_SCRATCH_GPR	(RSET_RANGE(RID_R2, RID_R5+1)|RID2RSET(RID_R14))
#define RSET_SCRATCH_FPR	RSET_RANGE(RID_F0, RID_F7+1)
#define RSET_SCRATCH		(RSET_SCRATCH_GPR|RSET_SCRATCH_FPR)
#define REGARG_FIRSTGPR		RID_R2
#define REGARG_LASTGPR		RID_R6
#define REGARG_NUMGPR		5
#define REGARG_FIRSTFPR		RID_F0
#define REGARG_LASTFPR		RID_F6
#define REGARG_NUMFPR		4

/* -- Spill slots --------------------------------------------------------- */

/* Spill slots are 32 bit wide. An even/odd pair is used for FPRs.
**
** SPS_FIXED: Available fixed spill slots in interpreter frame.
** This definition must match with the vm_s390x.dasc file.
** Slots 0-39 are the 160 byte register save area for callees (ABI).
** Slots 40-41 are the temporary slot SPOFS_TMP.
**
** SPS_FIRST: First spill slot for general use.
*/
#define SPS_FIXED	42
#define SPS_FIRST	42

#define SPOFS_TMP	(40*4)

#define sps_scale(slot)		(4 * (int32_t)(slot))
#define sps_align(slot)		(((slot) - SPS_FIXED + 1) & ~1)

/* -- Exit state ---------------------------------------------------------- */

/* This definition must match with the *.dasc file(s). */
typedef struct {
  lua_Number fpr[RID_NUM_FPR];	/* Floating-point registers. */
  intptr_t gpr[RID_NUM_GPR];	/* General-purpose registers. */
  int32_t spill[256];		/* Spill slots. */
} ExitState;

/* Highest exit + 1 indicates stack check. */
#define EXITSTATE_CHECKEXIT	1

/* Return the address of a per-trace exit stub. */
static LJ_AINLINE uint16_t *exitstub_trace_addr_(uint16_t *p, uint32_t exitno)
{
  while (*p == 0x0700) p++;  /* Skip NOPR. */
  p += p[0] == 0xc015 ? 3 : 4;  /* Skip BRASL or LG + BASR. */
  return p + 3*exitno;
}
/* Avoid dependence on lj_jit.h if only including lj_target.h. */
#define exitstub_trace_addr(T, exitno) \
  exitstub_trace_addr_((MCode *)((char *)(T)->mcode + (T)->szmcode), (exitno))

/* Check for valid field range. */
#define S390F_S_OK(x, b)	((((int64_t)(x) + (1LL << ((b)-1))) >> (b)) == 0)
#define S390F_U_OK(x, b)	((uint64_t)(x) < (1ULL << (b)))

/* -- Instructions -------------------------------------------------------- */

typedef enum s390xOp {
  /* RR-format instructions */
  SO_BCR   = 0x0700,
  SO_NOPR  = 0x0700,
  SO_BASR  = 0x0d00,
  SO_LCR   = 0x1300,
  SO_NR    = 0x1400,
  SO_CLR   = 0x1500,
  SO_XR    = 0x1700,
  SO_LR    = 0x1800,
  SO_CR    = 0x1900,
  SO_AR    = 0x1a00,
  SO_SR    = 0x1b00,
  SO_LDR   = 0x2800,
  /* RX-format instructions */
  SO_LA    = 0x4100,
  SO_N     = 0x5400,
  SO_STD   = 0x6000,
  SO_LD    = 0x6800,
  SO_STE   = 0x7000,
  SO_LE    = 0x7800,
  /* RI-format instructions */
  SO_NILL  = 0xa507,
  SO_TMLL  = 0xa701,
  SO_BRC   = 0xa704,
  SO_LGHI  = 0xa709,
  SO_AHI   = 0xa70a,
  SO_AGHI  = 0xa70b,
  SO_MGHI  = 0xa70d,
  /* RRE-format instructions */
  SO_MSR   = 0xb252,
  SO_LDEBR = 0xb304,
  SO_LPDBR = 0xb310,
  SO_LCDBR = 0xb313,
  SO_SQDBR = 0xb315,
  SO_CDBR  = 0xb319,
  SO_ADBR  = 0xb31a,
  SO_SDBR  = 0xb31b,
  SO_MDBR  = 0xb31c,
  SO_DDBR  = 0xb31d,
  SO_LEDBR = 0xb344,
  SO_CEFBR = 0xb394,
  SO_CDFBR = 0xb395,
  SO_CDGBR = 0xb3a5,
  SO_LDGR  = 0xb3c1,
  SO_LGDR  = 0xb3cd,
  SO_LTGR  = 0xb902,
  SO_LCGR  = 0xb903,
  SO_LGR   = 0xb904,
  SO_LGBR  = 0xb906,
  SO_LGHR  = 0xb907,
  SO_AGR   = 0xb908,
  SO_SGR   = 0xb909,
  SO_MSGR  = 0xb90c,
  SO_LRVGR = 0xb90f,
  SO_LGFR  = 0xb914,
  SO_LLGFR = 0xb916,
  SO_ALGFR = 0xb91a,
  SO_SLGFR = 0xb91b,
  SO_MSGFR = 0xb91c,
  SO_LRVR  = 0xb91f,
  SO_CGR   = 0xb920,
  SO_CLGR  = 0xb921,
  SO_CGFR  = 0xb930,
  SO_NGR   = 0xb980,
  SO_OGR   = 0xb981,
  SO_XGR   = 0xb982,
  SO_LLGCR = 0xb984,
  SO_LLGHR = 0xb985,
  /* RRF-format instructions */
  SO_FIDBR  = 0xb35f,
  SO_CELFBR = 0xb390,
  SO_CDLFBR = 0xb391,
  SO_CFDBR  = 0xb399,
  SO_CDLGBR = 0xb3a1,
  SO_CGDBR  = 0xb3a9,
  SO_CLGDBR = 0xb3ad,
  SO_LOCGR  = 0xb9e2,
  SO_NGRK   = 0xb9e4,
  SO_OGRK   = 0xb9e6,
  SO_XGRK   = 0xb9e7,
  SO_AGRK   = 0xb9e8,
  SO_SGRK   = 0xb9e9,
  SO_LOCR   = 0xb9f2,
  SO_XRK    = 0xb9f7,
  SO_ARK    = 0xb9f8,
  SO_SRK    = 0xb9f9,
  /* RIL-format instructions */
  SO_LARL  = 0xc000,
  SO_LGFI  = 0xc001,
  SO_BRCL  = 0xc004,
  SO_BRASL = 0xc005,
  SO_XIHF  = 0xc006,
  SO_XILF  = 0xc007,
  SO_IIHF  = 0xc008,
  SO_NIHF  = 0xc00a,
  SO_NILF  = 0xc00b,
  SO_OIHF  = 0xc00c,
  SO_OILF  = 0xc00d,
  SO_LLIHF = 0xc00e,
  SO_LLILF = 0xc00f,
  SO_MSGFI = 0xc200,
  SO_MSFI  = 0xc201,
  SO_AGFI  = 0xc208,
  SO_AFI   = 0xc209,
  SO_CGFI  = 0xc20c,
  SO_CFI   = 0xc20d,
  SO_CLGFI = 0xc20e,
  SO_CLFI  = 0xc20f,
  SO_CLIH  = 0xcc0f,
  /* RXY-format instructions */
  SO_LTG   = 0xe302,
  SO_LG    = 0xe304,
  SO_AG    = 0xe308,
  SO_LGF   = 0xe314,
  SO_LGH   = 0xe315,
  SO_LLGF  = 0xe316,
  SO_CG    = 0xe320,
  SO_STG   = 0xe324,
  SO_STY   = 0xe350,
  SO_STHY  = 0xe370,
  SO_LAY   = 0xe371,
  SO_STCY  = 0xe372,
  SO_LGB   = 0xe377,
  SO_LLGC  = 0xe390,
  SO_LLGH  = 0xe391,
  /* SIL-format instructions */
  SO_MVHI  = 0xe54c,
  /* RSY-format instructions */
  SO_SRAG  = 0xeb0a,
  SO_SRLG  = 0xeb0c,
  SO_SLLG  = 0xeb0d,
  SO_RLLG  = 0xeb1c,
  SO_RLL   = 0xeb1d,
  SO_SRAK  = 0xebdc,
  SO_SRLK  = 0xebde,
  SO_SLLK  = 0xebdf,
  /* RIE-f format instructions */
  SO_RISBG = 0xec55,
  /* RIE-c format instructions */
  SO_CGIJ  = 0xec7c,
  SO_CLGIJ = 0xec7d,
  SO_CIJ   = 0xec7e,
  SO_CLIJ  = 0xec7f,
  /* RIE-d, but encodes like RIE-c. */
  SO_AHIK  = 0xecd8,
  SO_AGHIK = 0xecd9,
  /* RXE, but encodes like RXY with dh2 = 0. */
  SO_CDB   = 0xed19,
  SO_LDY   = 0xed65,
  SO_LEY   = 0xed64,
  SO_STDY  = 0xed67,
  SO_STEY  = 0xed66,
} s390xOp;

/* Condition code masks. */
typedef enum s390xCC {
  CC_NOP, CC_O, CC_H, CC_NLE, CC_L, CC_NHE, CC_LH, CC_NE,
  CC_E, CC_NLH, CC_HE, CC_NL, CC_LE, CC_NH, CC_NO, CC_UNCOND
} s390xCC;

#endif
