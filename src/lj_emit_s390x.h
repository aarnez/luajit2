/*
** s390x instruction emitter.
** Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
**
** Contributed by Andreas Arnez, IBM Corp.
*/

/* -- Emit basic instructions --------------------------------------------- */

/* op1:8 r1:4 op2:4 i2:16 */
static void emit_ri(ASMState *as, uint16_t op, Reg r1, int16_t i2)
{
  *--as->mcp = (uint16_t)i2;
  *--as->mcp = op | ((r1 & 0xf) << 4);
}

/* op:8 r1:4 r2:4 */
static void emit_rr(ASMState *as, uint16_t op, Reg r1, Reg r2)
{
  *--as->mcp = op | ((r1 & 0xf) << 4) | (r2 & 0xf);
}

/* op:16 0:8 r1:4 r2:4 */
static void emit_rre(ASMState *as, uint16_t op, Reg r1, Reg r2)
{
  *--as->mcp = ((r1 & 0xf) << 4) | (r2 & 0xf);
  *--as->mcp = op;
}

/* op:16 m3:4 0:4 r1:4 r2:4 */
static void emit_rrf(ASMState *as, uint16_t op, Reg r1, Reg r2, uint8_t m3)
{
  *--as->mcp = ((uint16_t)m3 << 12) | ((r1 & 0xf) << 4) | (r2 & 0xf);
  *--as->mcp = op;
}

/* op1:8 r1:4 op2:4 i2:32 */
static void emit_ril(ASMState *as, uint16_t op, Reg r1, int32_t i2)
{
  *--as->mcp = (uint32_t)i2 & 0xffff;
  *--as->mcp = (uint32_t)i2 >> 16;
  *--as->mcp = op | ((r1 & 0xf) << 4);
}

/* op1:8 r1:4 m3:4 ri4:16 i2:8 op2:8 */
static void emit_riec(ASMState *as, s390xOp op, Reg r1, uint8_t m3,
		      int32_t ri4, uint8_t i2)
{
  *--as->mcp = ((uint16_t)i2 << 8) | (op & 0xff);
  *--as->mcp = ri4;
  *--as->mcp = (op & 0xff00) | ((r1 & 0xf) << 4) | (m3 & 0xf);
}

/* op1:8 r1:4 r2:4 i3:8 i4:8 i5:8 op2:8 */
static void emit_rief(ASMState *as, s390xOp op, Reg r1, Reg r2,
		      uint8_t i3, uint8_t i4, uint8_t i5)
{
  *--as->mcp = (i5 << 8) | (op & 0xff);
  *--as->mcp = (i3 << 8) | i4;
  *--as->mcp = (op & 0xff00) | ((r1 & 0xf) << 4) | (r2 & 0xf);
}

/* op:8 r1:4 x2:4 b2:4 d2:12 */
static void emit_rx(ASMState *as, uint16_t op, Reg r1, Reg x2,
		    Reg b2, uint32_t d2)
{
  *--as->mcp = (d2 & 0xfff) | ((b2 & 0xf) << 12);
  *--as->mcp = op | ((r1 & 0xf) << 4) | (x2 & 0xf);
}

/* op1:8 r1:4 x2:4 b2:4 dl2:12 dh2:8 op2:8 */
static void emit_rxy(ASMState *as, uint16_t op, Reg r1, Reg x2,
		     Reg b2, int32_t d2)
{
  *--as->mcp = ((d2 >> 4) & 0xff00) | (op & 0xff);
  *--as->mcp = (d2 & 0xfff) | ((b2 & 0xf) << 12);
  *--as->mcp = (op & 0xff00) | ((r1 & 0xf) << 4) | (x2 & 0xf);
}

static LJ_AINLINE int brcl_reachable(MCode *p, MCode *target)
{
  return checki32(target - p);
}

/* -- Emit loads/stores --------------------------------------------------- */

/* Prefer rematerialization of BASE/L from global_State over spills. */
#define emit_canremat(ref)	((ref) <= REF_BASE)

#define glofs(as, k) \
  ((intptr_t)((uintptr_t)(k) - (uintptr_t)J2G(as->J)))

/* Load a 32 bit constant into a GPR. */
static void emit_loadi(ASMState *as, Reg rd, int32_t i)
{
  if (checki16(i))
    emit_ri(as, SO_LGHI, rd, (int16_t)i);
  else
    emit_ril(as, SO_LGFI, rd, i);
}

/* Load a 64 bit constant into a GPR. */
static void emit_loadu64(ASMState *as, Reg rd, uint64_t u64)
{
  if (checki32((int64_t)u64)) {
    emit_loadi(as, rd, u64);
  } else if (checku32(u64)) {
    emit_ril(as, SO_LLILF, rd, u64);
  } else if ((u64 & 0xffffffff) == 0) {
    emit_ril(as, SO_LLIHF, rd, (int32_t)(u64 >> 32));
  } else if (u64 % 2 == 0 && brcl_reachable(as->mcp - 3, (MCode *)u64)) {
    emit_ril(as, SO_LARL, rd, (MCode *)u64 - (as->mcp - 3));
  } else {
    emit_ril(as, SO_IIHF, rd, u64 >> 32);
    emit_ril(as, SO_LLILF, rd, u64);
  }
}

static Reg ra_allock(ASMState *as, intptr_t k, RegSet allow);

/* Get/set from constant pointer. */
static void emit_lsptr(ASMState *as, Reg r, void *p, int st)
{
  intptr_t disp = glofs(as, p);
  if (S390F_S_OK(disp, 20)) {
    emit_rxy(as, st ? SO_STG : SO_LG, r, 0, RID_JGL, disp);
  } else {
    Reg base = ra_allock(as, (intptr_t)p, rset_exclude(RSET_GPR, r));
    emit_rxy(as, st ? SO_STG : SO_LG, r, 0, base, 0);
  }
}

/* Load address with LA or LAY. */
static void emit_ldaddr(ASMState *as, Reg r1, Reg x2, Reg b2, int32_t d2)
{
  if (S390F_U_OK(d2, 12))
    emit_rx(as, SO_LA, r1, x2, b2, d2);
  else
    emit_rxy(as, SO_LAY, r1, x2, b2, d2);
}

/* Load 64 bit IR constant into register. */
static void emit_loadk64(ASMState *as, Reg r, IRIns *ir)
{
  const uint64_t *k = &ir_k64(ir)->u64;
  if (r >= RID_MAX_GPR) {
    intptr_t disp = glofs(as, k);
    if (S390F_U_OK(disp, 12)) {
      emit_rx(as, SO_LD, r, 0, RID_JGL, disp);
    } else if (S390F_S_OK(disp, 20)) {
      emit_rxy(as, SO_LDY, r, 0, RID_JGL, disp);
    } else {
      Reg base = ra_allock(as, (intptr_t)k, RSET_GPR);
      emit_rx(as, SO_LD, r, 0, base, 0);
    }
  } else {
    emit_loadu64(as, r, *k);
  }
}

/* Get/set global_State fields. */
static void emit_lsglptr(ASMState *as, int st, Reg r, int32_t ofs)
{
  emit_rxy(as, st ? SO_STG : SO_LG, r, 0, RID_JGL, ofs);
}

#define emit_getgl(as, r, field) \
  emit_lsglptr(as, 0, (r), (int32_t)offsetof(global_State, field))
#define emit_setgl(as, r, field) \
  emit_lsglptr(as, 1, (r), (int32_t)offsetof(global_State, field))

/* Store trace number in vmstate, for the exit handler. */
static void emit_setvmstate(ASMState *as, int32_t i)
{
  int32_t disp = (int32_t)offsetof(global_State, vmstate);
  if (checki16(i) && S390F_U_OK(disp, 12)) {
    /* MVHI disp(JGL), i -- SIL format: op:16 b1:4 d1:12 i2:16 */
    *--as->mcp = i;
    *--as->mcp = (RID_JGL << 12) | disp;
    *--as->mcp = SO_MVHI;
  } else {
    emit_rxy(as, SO_STY, RID_R0, 0, RID_JGL, disp);
    emit_loadi(as, RID_R0, i);
  }
}

/* -- Emit control-flow instructions -------------------------------------- */

/* Label for internal jumps. */
typedef MCode *MCLabel;

/* Return label pointing to current PC. */
#define emit_label(as)		((as)->mcp)

static LJ_AINLINE void emit_brcl_at(MCode *p, s390xCC cond, MCode *target)
{
  intptr_t ri2 = target - p;
  p[0] = SO_BRCL | (cond << 4);
  p[1] = ri2 >> 16;
  p[2] = ri2;
}

static LJ_AINLINE void emit_brc_at(MCode *p, s390xCC cond, MCode *target)
{
  p[0] = SO_BRC | (cond << 4);
  p[1] = target - p;
}

static void emit_cond_branch(ASMState *as, s390xCC cond, MCode *target)
{
  MCode *p = as->mcp - 3;
  as->mcp = p;
  emit_brcl_at(p, cond, target);
}

#define emit_jmp(as, target)	emit_cond_branch(as, CC_UNCOND, (target))

static void emit_call(ASMState *as, ASMFunction target)
{
  MCode *t = (MCode *)(void *)target;
  if (brcl_reachable(as->mcp - 3, t)) {
    emit_ril(as, SO_BRASL, RID_R14, t - (as->mcp - 3));
  } else {
    emit_rr(as, SO_BASR, RID_R14, RID_R1);
    emit_loadu64(as, RID_R1, (uint64_t)(uintptr_t)target);
  }
}

/* -- Emit generic operations --------------------------------------------- */

/* Generic move between two regs. */
static void emit_movrr(ASMState *as, IRIns *ir, Reg dst, Reg src)
{
  if (dst == src) return;
  if (ir && irt_isnum(ir->t))
    emit_rr(as, SO_LDR, dst, src);
  else
    emit_rre(as, SO_LGR, dst, src);
}

/* Generic load of register with base and (small) offset address. */
static void emit_loadofs(ASMState *as, IRIns *ir, Reg r, Reg base, int32_t ofs)
{
  if (ir && irt_isnum(ir->t)) {
    if (S390F_U_OK(ofs, 12))
      emit_rx(as, SO_LD, r, 0, base, (uint32_t)ofs);
    else
      emit_rxy(as, SO_LDY, r, 0, base, ofs);
  } else if (ir && irt_isfloat(ir->t)) {
    if (S390F_U_OK(ofs, 12))
      emit_rx(as, SO_LE, r, 0, base, (uint32_t)ofs);
    else
      emit_rxy(as, SO_LEY, r, 0, base, ofs);
  } else if (ir && !irt_is64(ir->t)) {
    emit_rxy(as, SO_LGF, r, 0, base, ofs);
  } else {
    emit_rxy(as, SO_LG, r, 0, base, ofs);
  }
}

/* Generic store of register with base and (small) offset address. */
static void emit_storeofs(ASMState *as, IRIns *ir, Reg r, Reg base, int32_t ofs)
{
  if (ir && irt_isnum(ir->t)) {
    if (S390F_U_OK(ofs, 12))
      emit_rx(as, SO_STD, r, 0, base, (uint32_t)ofs);
    else
      emit_rxy(as, SO_STDY, r, 0, base, ofs);
  } else if (ir && irt_isfloat(ir->t)) {
    if (S390F_U_OK(ofs, 12))
      emit_rx(as, SO_STE, r, 0, base, (uint32_t)ofs);
    else
      emit_rxy(as, SO_STEY, r, 0, base, ofs);
  } else if (ir && !irt_is64(ir->t)) {
    emit_rxy(as, SO_STY, r, 0, base, ofs);
  } else {
    emit_rxy(as, SO_STG, r, 0, base, ofs);
  }
}

/* Add offset to pointer. */
static void emit_addptr(ASMState *as, Reg r, int32_t ofs)
{
  if (ofs == 0) return;
  if (checki16(ofs))
    emit_ri(as, SO_AGHI, r, (int16_t)ofs);
  else
    emit_ril(as, SO_AGFI, r, ofs);
}

#define emit_spsub(as, ofs)	emit_addptr(as, RID_SP, -(ofs))
