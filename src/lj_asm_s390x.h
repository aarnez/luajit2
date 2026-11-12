/*
** s390x IR assembler (SSA IR -> machine code).
** Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
**
** Contributed by Andreas Arnez, IBM Corp.
*/

/* -- Register allocator extensions --------------------------------------- */

/* Allocate a register with a hint. */
static Reg ra_hintalloc(ASMState *as, IRRef ref, Reg hint, RegSet allow)
{
  Reg r = IR(ref)->r;
  if (ra_noreg(r)) {
    if (!ra_hashint(r) && !iscrossref(as, ref))
      ra_sethint(IR(ref)->r, hint);  /* Propagate register hint. */
    r = ra_allocref(as, ref, allow);
  }
  ra_noweak(as, r);
  return r;
}

/* Allocate two source registers for three-operand instructions. */
static Reg ra_alloc2(ASMState *as, IRIns *ir, RegSet allow)
{
  IRIns *irl = IR(ir->op1), *irr = IR(ir->op2);
  Reg left = irl->r, right = irr->r;
  if (ra_hasreg(left)) {
    ra_noweak(as, left);
    if (ra_noreg(right))
      right = ra_allocref(as, ir->op2, rset_exclude(allow, left));
    else
      ra_noweak(as, right);
  } else if (ra_hasreg(right)) {
    ra_noweak(as, right);
    left = ra_allocref(as, ir->op1, rset_exclude(allow, right));
  } else if (ra_hashint(right)) {
    right = ra_allocref(as, ir->op2, allow);
    left = ra_alloc1(as, ir->op1, rset_exclude(allow, right));
  } else {
    left = ra_allocref(as, ir->op1, allow);
    right = ra_alloc1(as, ir->op2, rset_exclude(allow, left));
  }
  return left | (right << 8);
}

/* -- Guard handling ------------------------------------------------------ */

/* Setup all needed exit stubs. */
static void asm_exitstub_setup(ASMState *as, ExitNo nexits)
{
  ExitNo i;
  int rel;
  uint32_t ri2;
  MCode *target = (MCode *)(void *)lj_vm_exit_handler;
  MCode *mxp = as->mctop;
  if (mxp - (3*nexits + 4 + MCLIM_REDZONE) < as->mclim)
    asm_mclimit(as);
  rel = brcl_reachable(mxp - 3*nexits - 3, target);
  /*  rel: 0: brasl r1, ->vm_exit_handler
  ** !rel: 0: lg r1, [JGL, K64_VXH]; basr r1, r1
  **          brasl r0, <0; brasl r0, <0; ...
  */
  for (i = nexits-1; (int32_t)i >= 0; i--) {
    ri2 = -3*i - (rel ? 3 : 4);
    *--mxp = ri2;
    *--mxp = ri2 >> 16;
    *--mxp = SO_BRASL | (RID_R0 << 4);
  }
  as->mcexit = mxp;
  if (rel) {
    ri2 = target - (mxp-3);
    *--mxp = ri2;
    *--mxp = ri2 >> 16;
    *--mxp = SO_BRASL | (RID_R1 << 4);
  } else {
    int32_t disp = glofs(as, &as->J->k64[LJ_K64_VM_EXIT_HANDLER]);
    *--mxp = SO_BASR | (RID_R1 << 4) | RID_R1;
    *--mxp = ((disp >> 4) & 0xff00) | (SO_LG & 0xff);
    *--mxp = (disp & 0xfff) | (RID_JGL << 12);
    *--mxp = (SO_LG & 0xff00) | (RID_R1 << 4);
  }
  as->mctop = mxp;
}

static MCode *asm_exitstub_addr(ASMState *as, ExitNo exitno)
{
  /* Keep this in-sync with exitstub_trace_addr(). */
  return as->mcexit + 3*exitno;
}

/* Emit conditional branch to exit for guard. */
static void asm_guardcc(ASMState *as, s390xCC cc)
{
  MCode *target = asm_exitstub_addr(as, as->snapno);
  MCode *p = as->mcp;
  if (LJ_UNLIKELY(p == as->invmcp)) {
    as->loopinv = 1;
    emit_brcl_at(p, CC_UNCOND, target);
    as->mcp = p - 3;
    emit_brcl_at(p - 3, cc ^ CC_UNCOND, p);
    return;
  }
  emit_cond_branch(as, cc, target);
}

/* -- Operand fusion ------------------------------------------------------ */

/* Limit linear search to this distance. Avoids O(n^2) behavior. */
#define CONFLICT_SEARCH_LIM	31

static int asm_isk32(ASMState *as, IRRef ref, int32_t *k)
{
  UNUSED(as);
  if (irref_isk(ref)) {
    IRIns *ir = IR(ref);
    if (ir->o == IR_KINT64) {
      int64_t v = (int64_t)ir_k64(ir)->u64;
      if (v == (int64_t)(int32_t)v) { *k = (int32_t)v; return 1; }
      return 0;
    } else if (LJ_GC64 && (ir->o == IR_KPTR || ir->o == IR_KKPTR)) {
      int64_t v = (int64_t)ir_kptr(ir);
      if (v == (int64_t)(int32_t)v) { *k = (int32_t)v; return 1; }
      return 0;
    } else if (LJ_GC64 && ir->o == IR_KGC) {
      return 0;
    }
    *k = ir->i;
    return 1;
  }
  return 0;
}

/* Check if there's no conflicting instruction between curins and ref. */
static int noconflict(ASMState *as, IRRef ref, IROp conflict)
{
  IRIns *ir = as->ir;
  IRRef i = as->curins;
  if (i > ref + CONFLICT_SEARCH_LIM)
    return 0;  /* Give up, ref is too far away. */
  while (--i > ref)
    if (ir[i].o == conflict)
      return 0;  /* Conflict found. */
  return 1;  /* Ok, no conflict. */
}

/* Check for an integer with undefined upper bits. */
static int asm_isnarrow(ASMState *as, IRRef ref)
{
  IRIns *ir = IR(ref);
  return !irref_isk(ref) && (irt_isint(ir->t) || irt_isu32(ir->t));
}

/* Fuse the array base of colocated arrays. */
static int32_t asm_fuseabase(ASMState *as, IRRef ref)
{
  IRIns *ir = IR(ref);
  if (ir->o == IR_TNEW && ir->op1 <= LJ_MAX_COLOSIZE &&
      !neverfuse(as) && noconflict(as, ref, IR_NEWREF))
    return (int32_t)sizeof(GCtab);
  return 0;
}

/* Fuse array/hash/upvalue reference into register+offset operand. */
static Reg asm_fuseahuref(ASMState *as, IRRef ref, int32_t *ofsp, RegSet allow)
{
  IRIns *ir = IR(ref);
  if (ra_noreg(ir->r)) {
    if (ir->o == IR_AREF) {
      if (mayfuse(as, ref)) {
	if (irref_isk(ir->op2)) {
	  IRRef tab = IR(ir->op1)->op1;
	  int32_t ofs = asm_fuseabase(as, tab);
	  IRRef refa = ofs ? tab : ir->op1;
	  ofs += 8*IR(ir->op2)->i;
	  if (S390F_S_OK(ofs, 20)) {
	    *ofsp = ofs;
	    return ra_alloc1(as, refa, allow);
	  }
	}
      }
    } else if (ir->o == IR_HREFK) {
      if (mayfuse(as, ref)) {
	int32_t ofs = (int32_t)(IR(ir->op2)->op2 * sizeof(Node));
	if (S390F_S_OK(ofs, 20)) {
	  *ofsp = ofs;
	  return ra_alloc1(as, ir->op1, allow);
	}
      }
    } else if (ir->o == IR_UREFC) {
      if (irref_isk(ir->op1)) {
	GCfunc *fn = ir_kfunc(IR(ir->op1));
	GCupval *uv = &gcref(fn->l.uvptr[(ir->op2 >> 8)])->uv;
	int32_t ofs = (int32_t)((intptr_t)&uv->tv - (intptr_t)J2G(as->J));
	if (S390F_S_OK(ofs, 20)) {
	  *ofsp = ofs;
	  return RID_JGL;
	}
      }
    } else if (ir->o == IR_TMPREF) {
      *ofsp = (int32_t)(offsetof(global_State, tmptv));
      return RID_JGL;
    }
  }
  *ofsp = 0;
  return ra_alloc1(as, ref, allow);
}

/* Fuse XLOAD/XSTORE reference into load/store operand. */
static void asm_fusexref(ASMState *as, s390xOp op, Reg rd, IRRef ref,
			 RegSet allow)
{
  IRIns *ir = IR(ref);
  Reg base;
  int32_t ofs = 0;
  if (ra_noreg(ir->r) && canfuse(as, ir)) {
    if (ir->o == IR_ADD) {
      if (asm_isk32(as, ir->op2, &ofs) && S390F_S_OK(ofs, 20))
	ref = ir->op1;
    } else if (ir->o == IR_STRREF) {
      if (asm_isk32(as, ir->op2, &ofs)) {
	ref = ir->op1;
      } else if (asm_isk32(as, ir->op1, &ofs)) {
	ref = ir->op2;
      } else {
	Reg left = ra_alloc1(as, ir->op1, allow);
	Reg right = ra_alloc1(as, ir->op2, rset_exclude(allow, left));
	emit_rxy(as, op, rd, left, RID_TMP, sizeof(GCstr));
	emit_rre(as, SO_LLGFR, RID_TMP, right);
	return;
      }
      if (S390F_S_OK(ofs + sizeof(GCstr), 20)) {
	ofs += sizeof(GCstr);
      } else {
	Reg rn = ra_alloc1(as, ref, allow);
	Reg rm = ra_allock(as, ofs, rset_exclude(allow, rn));
	emit_rxy(as, op, rd, rm, rn, sizeof(GCstr));
	return;
      }
    }
  }
  base = ra_alloc1(as, ref, allow);
  emit_rxy(as, op, rd, 0, base, ofs);
}

/* -- Calls --------------------------------------------------------------- */

/* Generate a call to a C function. */
static void asm_gencall(ASMState *as, const CCallInfo *ci, IRRef *args)
{
  uint32_t n, nargs = CCI_XNARGS(ci);
  int32_t spofs = 160;  /* Skip register save area. */
  Reg gpr, fpr = REGARG_FIRSTFPR;
  if (ci->func)
    emit_call(as, ci->func);
  /* r6 is an argument register, but callee-saved. Don't touch its cost. */
  for (gpr = REGARG_FIRSTGPR; gpr <= REGARG_LASTGPR; gpr++)
    if (rset_test(RSET_SCRATCH_GPR, gpr))
      as->cost[gpr] = REGCOST(~0u, ASMREF_L);
  gpr = REGARG_FIRSTGPR;
  for (n = 0; n < nargs; n++) {  /* Setup args. */
    IRRef ref = args[n];
    if (ref) {
      IRIns *ir = IR(ref);
      if (irt_isfp(ir->t)) {
	if (fpr <= REGARG_LASTFPR) {
	  lj_assertA(rset_test(as->freeset, fpr),
		     "reg %d not free", fpr);  /* Must have been evicted. */
	  ra_leftov(as, fpr, ref);
	  fpr += 2;  /* FPR args are f0, f2, f4, f6. */
	} else {
	  Reg r = ra_alloc1(as, ref, RSET_FPR);
	  if (irt_isfloat(ir->t))
	    emit_rx(as, SO_STE, r, 0, RID_SP, (uint32_t)(spofs + 4));
	  else
	    emit_spstore(as, ir, r, spofs);
	  spofs += 8;
	}
      } else {
	if (gpr <= REGARG_LASTGPR) {
	  lj_assertA(rset_test(as->freeset, gpr),
		     "reg %d not free", gpr);  /* Must have been evicted. */
	  if (asm_isnarrow(as, ref))
	    emit_rre(as, irt_isint(ir->t) ? SO_LGFR : SO_LLGFR, gpr, gpr);
	  ra_leftov(as, gpr, ref);
	  gpr++;
	} else {
	  Reg r = ra_alloc1(as, ref, RSET_GPR);
	  if (asm_isnarrow(as, ref)) {
	    emit_rxy(as, SO_STG, RID_TMP, 0, RID_SP, spofs);
	    emit_rre(as, irt_isint(ir->t) ? SO_LGFR : SO_LLGFR, RID_TMP, r);
	  } else {
	    emit_rxy(as, SO_STG, r, 0, RID_SP, spofs);
	  }
	  spofs += 8;
	}
      }
    }
  }
}

/* Setup result reg/sp for call. Evict scratch regs. */
static void asm_setupresult(ASMState *as, IRIns *ir, const CCallInfo *ci)
{
  RegSet drop = RSET_SCRATCH;
  int hiop = ((ir+1)->o == IR_HIOP && !irt_isnil((ir+1)->t));
  /* The callee-saved r6 is clobbered if it's used as an argument register. */
  if (CCI_NARGS(ci) >= REGARG_NUMGPR)
    drop |= RID2RSET(REGARG_LASTGPR);
  if (ra_hasreg(ir->r))
    rset_clear(drop, ir->r);  /* Dest reg handled below. */
  if (hiop && ra_hasreg((ir+1)->r))
    rset_clear(drop, (ir+1)->r);  /* Dest reg handled below. */
  ra_evictset(as, drop);  /* Evictions must be performed first. */
  if (ra_used(ir)) {
    lj_assertA(!irt_ispri(ir->t), "PRI dest");
    if (irt_isfp(ir->t)) {
      if (ci->flags & CCI_CASTU64) {
	Reg dest = ra_dest(as, ir, RSET_FPR);
	emit_rre(as, SO_LDGR, dest, RID_RET);
      } else {
	ra_destreg(as, ir, RID_FPRET);
      }
    } else if (hiop) {
      ra_destpair(as, ir);
    } else {
      ra_destreg(as, ir, RID_RET);
    }
  }
  UNUSED(ci);
}

static void asm_callx(ASMState *as, IRIns *ir)
{
  IRRef args[CCI_NARGS_MAX*2];
  CCallInfo ci;
  IRRef func;
  IRIns *irf;
  ci.flags = asm_callx_flags(as, ir);
  asm_collectargs(as, ir, &ci, args);
  asm_setupresult(as, ir, &ci);
  func = ir->op2; irf = IR(func);
  if (irf->o == IR_CARG) { func = irf->op1; irf = IR(func); }
  if (irref_isk(func)) {  /* Call to constant address. */
    ci.func = (ASMFunction)(ir_k64(irf)->u64);
  } else {  /* Need a non-argument register for indirect calls. */
    Reg freg = ra_alloc1(as, func,
			 RSET_GPR - RSET_RANGE(REGARG_FIRSTGPR, REGARG_LASTGPR+1));
    emit_rr(as, SO_BASR, RID_R14, freg);
    ci.func = (ASMFunction)(void *)0;
  }
  asm_gencall(as, &ci, args);
}

/* -- Returns ------------------------------------------------------------- */

/* Return to lower frame. Guard that it goes to the right spot. */
static void asm_retf(ASMState *as, IRIns *ir)
{
  Reg base = ra_alloc1(as, REF_BASE, RSET_GPR);
  void *pc = ir_kptr(IR(ir->op2));
  int32_t delta = 1+LJ_FR2+bc_a(*((const BCIns *)pc - 1));
  as->topslot -= (BCReg)delta;
  if ((int32_t)as->topslot < 0) as->topslot = 0;
  irt_setmark(IR(REF_BASE)->t);  /* Children must not coalesce with BASE reg. */
  emit_setgl(as, base, jit_base);
  emit_addptr(as, base, -8*delta);
  asm_guardcc(as, CC_NE);
  emit_rre(as, SO_CGR, RID_TMP,
	   ra_allock(as, i64ptr(pc), rset_exclude(RSET_GPR, base)));
  emit_rxy(as, SO_LG, RID_TMP, 0, base, -8);
}

/* -- Buffer operations --------------------------------------------------- */

#if LJ_HASBUFFER
static void asm_bufhdr_write(ASMState *as, Reg sb)
{
  Reg tmp = ra_scratch(as, rset_exclude(RSET_GPR, sb));
  IRIns irgc;
  irgc.ot = IRT(0, IRT_PGC);  /* GC type. */
  emit_storeofs(as, &irgc, RID_TMP, sb, offsetof(SBuf, L));
  emit_rief(as, SO_RISBG, RID_TMP, tmp, 63-lj_fls(SBUF_MASK_FLAG), 63, 0);
  emit_getgl(as, RID_TMP, cur_L);
  emit_loadofs(as, &irgc, tmp, sb, offsetof(SBuf, L));
}
#endif

/* -- Type conversions ---------------------------------------------------- */

static void asm_tointg(ASMState *as, IRIns *ir, Reg left)
{
  Reg tmp = ra_scratch(as, rset_exclude(RSET_FPR, left));
  Reg dest = ra_dest(as, ir, RSET_GPR);
  asm_guardcc(as, CC_NE);  /* Exit if NE or unordered. */
  emit_rre(as, SO_CDBR, tmp, left);
  emit_rre(as, SO_CDFBR, tmp, dest);
  emit_rrf(as, SO_CFDBR, dest, left, 5);  /* Round toward zero. */
}

static void asm_tobit(ASMState *as, IRIns *ir)
{
  Reg left = ra_alloc1(as, ir->op1, RSET_FPR);
  Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_FPR, left));
  Reg tmp = ra_scratch(as, rset_exclude(rset_exclude(RSET_FPR, left), right));
  Reg dest = ra_dest(as, ir, RSET_GPR);
  emit_rre(as, SO_LGDR, dest, tmp);
  emit_rre(as, SO_ADBR, tmp, right);
  emit_rr(as, SO_LDR, tmp, left);
}

static void asm_conv(ASMState *as, IRIns *ir)
{
  IRType st = (IRType)(ir->op2 & IRCONV_SRCMASK);
  int st64 = (st == IRT_I64 || st == IRT_U64 || st == IRT_P64);
  int stfp = (st == IRT_NUM || st == IRT_FLOAT);
  IRRef lref = ir->op1;
  lj_assertA(irt_type(ir->t) != st, "inconsistent types for CONV");
  if (irt_isfp(ir->t)) {
    Reg dest = ra_dest(as, ir, RSET_FPR);
    if (stfp) {  /* FP to FP conversion. */
      Reg left = ra_alloc1(as, lref, RSET_FPR);
      emit_rre(as, st == IRT_NUM ? SO_LEDBR : SO_LDEBR, dest, left);
    } else {  /* Integer to FP conversion. */
      Reg left = ra_alloc1(as, lref, RSET_GPR);
      if (st == IRT_INT)
	emit_rre(as, irt_isfloat(ir->t) ? SO_CEFBR : SO_CDFBR, dest, left);
      else if (st == IRT_U32)
	emit_rrf(as, irt_isfloat(ir->t) ? SO_CELFBR : SO_CDLFBR, dest, left, 0);
      else if (st == IRT_I64)
	emit_rre(as, SO_CDGBR, dest, left);
      else
	emit_rrf(as, SO_CDLGBR, dest, left, 0);
    }
  } else if (stfp) {  /* FP to integer conversion. */
    if (irt_isguard(ir->t)) {
      /* Checked conversions are only supported from number to int. */
      lj_assertA(irt_isint(ir->t) && st == IRT_NUM,
		 "bad type for checked CONV");
      asm_tointg(as, ir, ra_alloc1(as, lref, RSET_FPR));
    } else {
      Reg left = ra_alloc1(as, lref, RSET_FPR);
      Reg dest = ra_dest(as, ir, RSET_GPR);
      if (irt_isi64(ir->t)) {
	emit_rrf(as, SO_CGDBR, dest, left, 5);
      } else if (irt_isu64(ir->t)) {
	/* Use CGDBR for negative values and CLGDBR otherwise. */
	MCLabel l_end = emit_label(as);
	emit_rrf(as, SO_CLGDBR, dest, left, 5);
	emit_cond_branch(as, 0xe, l_end);
	emit_rrf(as, SO_CGDBR, dest, left, 5);
      } else {
	emit_rrf(as, SO_CFDBR, dest, left, 5);
      }
    }
  } else if (st >= IRT_I8 && st <= IRT_U16) {  /* Extend to 64 bit integer. */
    Reg dest = ra_dest(as, ir, RSET_GPR);
    Reg left = ra_alloc1(as, lref, RSET_GPR);
    switch (st) {
    case IRT_I8:  emit_rre(as, SO_LGBR,  dest, left); break;
    case IRT_U8:  emit_rre(as, SO_LLGCR, dest, left); break;
    case IRT_I16: emit_rre(as, SO_LGHR,  dest, left); break;
    case IRT_U16: emit_rre(as, SO_LLGHR, dest, left); break;
    default: lj_assertA(0, "bad CONV source type"); break;
    }
  } else {
    Reg dest = ra_dest(as, ir, RSET_GPR);
    if (irt_is64(ir->t)) {
      if (st64) {  /* 64/64 bit no-op (cast). */
	ra_leftov(as, dest, lref);  /* Do nothing, but may need to move regs. */
      } else if (ir->op2 & IRCONV_SEXT) {  /* 32 to 64 bit sign extension. */
	Reg left = ra_alloc1(as, lref, RSET_GPR);
	emit_rre(as, SO_LGFR, dest, left);
      } else {  /* 32 to 64 bit zero extension. */
	Reg left = ra_alloc1(as, lref, RSET_GPR);
	emit_rre(as, SO_LLGFR, dest, left);
      }
    } else {  /* 64 to 32 bit truncation or 32/32 bit no-op (cast). */
      ra_leftov(as, dest, lref);  /* Do nothing, but may need to move regs. */
    }
  }
}

static void asm_strto(ASMState *as, IRIns *ir)
{
  const CCallInfo *ci = &lj_ir_callinfo[IRCALL_lj_strscan_num];
  IRRef args[2];
  Reg tmp;
  int32_t ofs = 0;
  ra_evictset(as, RSET_SCRATCH);
  if (ra_used(ir)) {
    if (ra_hasspill(ir->s)) {
      ofs = sps_scale(ir->s);
      if (ra_hasreg(ir->r)) {
	ra_free(as, ir->r);
	ra_modified(as, ir->r);
	emit_spload(as, ir, ir->r, ofs);
      }
    } else {
      Reg dest = ra_dest(as, ir, RSET_FPR);
      emit_spload(as, ir, dest, 0);
    }
  }
  asm_guardcc(as, CC_E);
  emit_rre(as, SO_LTGR, RID_RET, RID_RET);
  args[0] = ir->op1;      /* GCstr *str */
  args[1] = ASMREF_TMP1;  /* TValue *n  */
  asm_gencall(as, ci, args);
  tmp = ra_releasetmp(as, ASMREF_TMP1);
  emit_ldaddr(as, tmp, 0, RID_SP, ofs);
}

/* -- Memory references --------------------------------------------------- */

/* Store tagged value for ref at base+ofs. */
static void asm_tvstore64(ASMState *as, Reg base, int32_t ofs, IRRef ref)
{
  RegSet allow = rset_exclude(RSET_GPR, base);
  IRIns *ir = IR(ref);
  lj_assertA(irt_ispri(ir->t) || irt_isaddr(ir->t) || irt_isinteger(ir->t),
	     "store of IR type %d", irt_type(ir->t));
  if (irref_isk(ref)) {
    TValue k;
    Reg tmp;
    lj_ir_kvalue(as->J->L, &k, ir);
    tmp = ra_allock(as, (intptr_t)k.u64, allow);
    emit_rxy(as, SO_STG, tmp, 0, base, ofs);
  } else {
    Reg src = ra_alloc1(as, ref, allow), tmp;
    rset_clear(allow, src);
    tmp = ra_scratch(as, allow);
    rset_clear(allow, tmp);
    emit_rxy(as, SO_STG, tmp, 0, base, ofs);
    if (irt_isinteger(ir->t)) {
      emit_ril(as, SO_IIHF, tmp, (int32_t)irt_toitype(ir->t) << 15);
      emit_rr(as, SO_LR, tmp, src);
    } else {
      emit_ril(as, SO_OIHF, tmp, (int32_t)irt_toitype(ir->t) << 15);
      emit_rre(as, SO_LGR, tmp, src);
    }
  }
}

/* Get pointer to TValue. */
static void asm_tvptr(ASMState *as, Reg dest, IRRef ref, MSize mode)
{
  int32_t tmpofs = (int32_t)(offsetof(global_State, tmptv));
  if ((mode & IRTMPREF_IN1)) {
    IRIns *ir = IR(ref);
    if (irt_isnum(ir->t)) {
      if ((mode & IRTMPREF_OUT1)) {
	Reg src = ra_alloc1(as, ref, RSET_FPR);
	emit_ldaddr(as, dest, 0, RID_JGL, tmpofs);
	if (S390F_U_OK(tmpofs, 12))
	  emit_rx(as, SO_STD, src, 0, RID_JGL, (uint32_t)tmpofs);
	else
	  emit_rxy(as, SO_STDY, src, 0, RID_JGL, tmpofs);
      } else if (irref_isk(ref)) {
	/* Use the number constant itself as a TValue. */
	ra_allockreg(as, (intptr_t)ir_knum(ir), dest);
      } else {
	/* Force spill and use spill slot. */
	int32_t spofs = ra_spill(as, ir);
	emit_ldaddr(as, dest, 0, RID_SP, spofs);
      }
    } else {
      emit_ldaddr(as, dest, 0, RID_JGL, tmpofs);
      asm_tvstore64(as, RID_JGL, tmpofs, ref);
    }
  } else {
    emit_ldaddr(as, dest, 0, RID_JGL, tmpofs);
  }
}

static void asm_aref(ASMState *as, IRIns *ir)
{
  RegSet allow = RSET_GPR;
  Reg dest = ra_dest(as, ir, allow);
  Reg idx, base;
  if (irref_isk(ir->op2)) {
    IRRef tab = IR(ir->op1)->op1;
    int32_t ofs = asm_fuseabase(as, tab);
    IRRef refa = ofs ? tab : ir->op1;
    ofs += 8*IR(ir->op2)->i;
    if (S390F_S_OK(ofs, 20)) {
      base = ra_alloc1(as, refa, allow);
      emit_ldaddr(as, dest, 0, base, ofs);
      return;
    }
  }
  base = ra_alloc1(as, ir->op1, rset_clear(allow, dest));
  idx = ra_alloc1(as, ir->op2, rset_clear(allow, base));
  emit_ldaddr(as, dest, dest, base, 0);
  emit_rief(as, SO_RISBG, dest, idx, 29, 0x80|60, 3);
}

/* Inlined hash lookup. Specialized for key type and for const keys.
** The equivalent C code is:
**   Node *n = hashkey(t, key);
**   do {
**     if (lj_obj_equal(&n->key, key)) return &n->val;
**   } while ((n = nextnode(n)));
**   return niltv(L);
**
** For non-constant number keys, CDB is used for the key comparison. It never
** matches tagged non-number keys, since they are all QNaNs. And it treats
** -0.0 and +0.0 as equal, so no canonicalization is needed.
*/
static void asm_href(ASMState *as, IRIns *ir, IROp merge)
{
  RegSet allow = RSET_GPR;
  int destused = ra_used(ir);
  Reg dest = ra_dest(as, ir, allow);
  Reg tab = ra_alloc1(as, ir->op1, rset_clear(allow, dest));
  Reg key = RID_NONE, tkey = RID_NONE;
  IRRef refkey = ir->op2;
  IRIns *irkey = IR(refkey);
  int isk = irref_isk(refkey);
  IRType1 kt = irkey->t;
  uint32_t khash;
  MCLabel l_end;
  MCode *l_loop;
  rset_clear(allow, tab);

  /* Allocate registers outside of the loop. */
  if (isk) {
    int64_t k;
    if (irt_isaddr(kt)) {
      k = (int64_t)(((uint64_t)irt_toitype(kt) << 47) |
		    (uint64_t)ir_kgc(irkey));
    } else if (irt_isnum(kt)) {
      k = (int64_t)ir_knum(irkey)->u64;
      /* Assumes -0.0 is already canonicalized to +0.0. */
    } else {
      lj_assertA(irt_ispri(kt) && !irt_isnil(kt), "bad HREF key type");
      k = (int64_t)~((uint64_t)~irt_toitype(kt) << 47);
    }
    tkey = ra_allock(as, k, allow);
  } else if (irt_isnum(kt)) {
    key = ra_alloc1(as, refkey, RSET_FPR);
  } else {
    lj_assertA(irt_isaddr(kt), "bad HREF key type");
    key = ra_alloc1(as, refkey, allow);
    tkey = ra_scratch(as, rset_clear(allow, key));
  }

  /* Key not found in chain: jump to exit (if merged) or load niltv. */
  l_end = emit_label(as);
  as->invmcp = NULL;
  if (merge == IR_NE)
    asm_guardcc(as, CC_UNCOND);
  else if (destused)
    emit_ldaddr(as, dest, 0, RID_JGL, offsetof(global_State, nilnode.val));

  /* Follow hash chain until the end. */
  l_loop = as->mcp -= 2;  /* Patched below. */
  emit_rxy(as, SO_LTG, dest, 0, dest, (int32_t)offsetof(Node, next));

  /* Type and value comparison. */
  if (merge == IR_EQ) {
    asm_guardcc(as, CC_E);
  } else {
    as->mcp -= 2;
    emit_brc_at(as->mcp, CC_E, l_end);
  }
  if (ra_hasreg(tkey))
    emit_rxy(as, SO_CG, tkey, 0, dest, (int32_t)offsetof(Node, key));
  else
    emit_rxy(as, SO_CDB, key, 0, dest, (int32_t)offsetof(Node, key));
  emit_brc_at(l_loop, CC_NE, as->mcp);
  checkmclim(as);

  /* Load main position relative to tab->node into dest. */
  khash = isk ? ir_khash(as, irkey) : 1;
  if (khash == 0) {
    emit_rxy(as, SO_LG, dest, 0, tab, (int32_t)offsetof(GCtab, node));
    return;
  }
  emit_rxy(as, SO_AG, dest, 0, tab, (int32_t)offsetof(GCtab, node));
  emit_ri(as, SO_MGHI, dest, (int16_t)sizeof(Node));
  if (isk) {
    emit_ril(as, SO_NILF, dest, (int32_t)khash);
    emit_rxy(as, SO_LLGF, dest, 0, tab, (int32_t)offsetof(GCtab, hmask));
    return;
  }
  emit_rx(as, SO_N, dest, 0, tab, (uint32_t)offsetof(GCtab, hmask));
  if (irt_isstr(kt)) {
    emit_rxy(as, SO_LLGF, dest, 0, key, (int32_t)offsetof(GCstr, sid));
  } else {
    /* Must match with hashrot() in lj_tab.h. lo in TMP, hi in dest. */
    emit_rr(as, SO_SR, dest, RID_TMP);
    emit_rxy(as, SO_RLL, RID_TMP, RID_TMP, 0, HASH_ROT3);
    emit_rr(as, SO_XR, dest, RID_TMP);
    emit_rxy(as, SO_RLL, dest, dest, 0, HASH_ROT2);
    emit_rr(as, SO_SR, RID_TMP, dest);
    emit_rxy(as, SO_RLL, dest, dest, 0, HASH_ROT1);
    if (irt_isnum(kt)) {
      emit_rr(as, SO_XR, RID_TMP, dest);
      emit_rief(as, SO_RISBG, dest, RID_TMP, 32, 0x80|62, 33);
      emit_rre(as, SO_LGDR, RID_TMP, key);
    } else {
      emit_rrf(as, SO_XRK, RID_TMP, tkey, dest);
      emit_rxy(as, SO_SRLG, dest, tkey, 0, 32);
    }
  }
  if (!irt_isnum(kt)) {  /* Construct tagged key: tkey = key | itype << 47. */
    emit_ril(as, SO_OIHF, tkey, irt_toitype(kt) << 15);
    emit_rre(as, SO_LGR, tkey, key);
  }
}

static void asm_hrefk(ASMState *as, IRIns *ir)
{
  IRIns *kslot = IR(ir->op2);
  IRIns *irkey = IR(kslot->op1);
  int32_t ofs = (int32_t)(kslot->op2 * sizeof(Node));
  int32_t kofs = ofs + (int32_t)offsetof(Node, key);
  int bigofs = !S390F_S_OK(kofs, 20);
  Reg dest = (ra_used(ir) || bigofs) ? ra_dest(as, ir, RSET_GPR) : RID_NONE;
  Reg node = ra_alloc1(as, ir->op1, RSET_GPR);
  Reg idx = node;
  RegSet allow = rset_exclude(RSET_GPR, node);
  uint64_t k;
  lj_assertA(ofs % sizeof(Node) == 0, "unaligned HREFK slot");
  if (bigofs) {
    idx = dest;
    rset_clear(allow, dest);
    kofs = (int32_t)offsetof(Node, key);
  } else if (ra_hasreg(dest)) {
    emit_addptr(as, dest, ofs);
    emit_rre(as, SO_LGR, dest, node);
  }
  asm_guardcc(as, CC_NE);
  if (irt_ispri(irkey->t)) {
    k = ~((uint64_t)~irt_toitype(irkey->t) << 47);
  } else if (irt_isnum(irkey->t)) {
    k = ir_knum(irkey)->u64;
  } else {
    k = ((uint64_t)irt_toitype(irkey->t) << 47) | (uint64_t)ir_kgc(irkey);
  }
  {
    Reg tmp = ra_scratch(as, allow);
    Reg kref = ra_allock(as, (int64_t)k, rset_exclude(allow, tmp));
    emit_rre(as, SO_CGR, tmp, kref);
    emit_rxy(as, SO_LG, tmp, 0, idx, kofs);
  }
  if (bigofs) {
    emit_addptr(as, dest, ofs);
    emit_rre(as, SO_LGR, dest, node);
  }
}

static void asm_uref(ASMState *as, IRIns *ir)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  int guarded = (irt_t(ir->t) & (IRT_GUARD|IRT_TYPE)) == (IRT_GUARD|IRT_PGC);
  if (irref_isk(ir->op1) && !guarded) {
    GCfunc *fn = ir_kfunc(IR(ir->op1));
    MRef *v = &gcref(fn->l.uvptr[(ir->op2 >> 8)])->uv.v;
    emit_lsptr(as, dest, v, 0);
  } else {
    if (ir->o == IR_UREFC)
      emit_addptr(as, dest, (int32_t)offsetof(GCupval, tv));
    else
      emit_rxy(as, SO_LG, dest, 0, dest, (int32_t)offsetof(GCupval, v));
    if (guarded) {
      asm_guardcc(as, ir->o == IR_UREFC ? CC_E : CC_NE);
      emit_rre(as, SO_LTGR, RID_TMP, RID_TMP);
      emit_rxy(as, SO_LLGC, RID_TMP, 0, dest,
	       (int32_t)offsetof(GCupval, closed));
    }
    if (irref_isk(ir->op1)) {
      GCfunc *fn = ir_kfunc(IR(ir->op1));
      uint64_t k = gcrefu(fn->l.uvptr[(ir->op2 >> 8)]);
      emit_loadu64(as, dest, k);
    } else {
      emit_rxy(as, SO_LG, dest, 0, ra_alloc1(as, ir->op1, RSET_GPR),
	       (int32_t)offsetof(GCfuncL, uvptr) +
	       (int32_t)sizeof(MRef) * (int32_t)(ir->op2 >> 8));
    }
  }
}

static void asm_fref(ASMState *as, IRIns *ir)
{
  UNUSED(as); UNUSED(ir);
  lj_assertA(!ra_used(ir), "unfused FREF");
}

static void asm_strref(ASMState *as, IRIns *ir)
{
  RegSet allow = RSET_GPR;
  Reg dest = ra_dest(as, ir, allow);
  Reg base = ra_alloc1(as, ir->op1, allow);
  IRIns *irr = IR(ir->op2);
  rset_clear(allow, base);
  if (irref_isk(ir->op2)) {
    intptr_t ofs = sizeof(GCstr) + irr->i;
    if (S390F_S_OK(ofs, 20)) {
      emit_ldaddr(as, dest, 0, base, ofs);
    } else {
      emit_addptr(as, dest, ofs);
      if (dest != base)
	emit_rre(as, SO_LGR, dest, base);
    }
  } else {
    Reg right = ra_alloc1(as, ir->op2, allow);
    emit_ldaddr(as, dest, RID_TMP, base, sizeof(GCstr));
    emit_rre(as, SO_LLGFR, RID_TMP, right);
  }
}

static void asm_fload(ASMState *as, IRIns *ir)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  Reg idx;
  int32_t ofs;
  if (ir->op1 == REF_NIL) {  /* FLOAD from GG_State with offset. */
    idx = RID_JGL;
    ofs = (ir->op2 << 2) - GG_OFS(g);
  } else {
    idx = ra_alloc1(as, ir->op1, RSET_GPR);
    if (ir->op2 == IRFL_TAB_ARRAY) {
      ofs = asm_fuseabase(as, ir->op1);
      if (ofs) {  /* Turn the t->array load into an add for colocated arrays. */
	emit_ldaddr(as, dest, 0, idx, ofs);
	return;
      }
    }
    ofs = field_ofs[ir->op2];
  }
  switch (irt_type(ir->t)) {
  case IRT_I8:  emit_rxy(as, SO_LGB,  dest, 0, idx, ofs); break;
  case IRT_U8:  emit_rxy(as, SO_LLGC, dest, 0, idx, ofs); break;
  case IRT_I16: emit_rxy(as, SO_LGH,  dest, 0, idx, ofs); break;
  case IRT_U16: emit_rxy(as, SO_LLGH, dest, 0, idx, ofs); break;
  default:
    if (irt_is64(ir->t))
      emit_rxy(as, SO_LG,   dest, 0, idx, ofs);
    else
      emit_rxy(as, SO_LLGF, dest, 0, idx, ofs);
    break;
  }
}

static void asm_fstore(ASMState *as, IRIns *ir)
{
  if (ir->r != RID_SINK) {
    Reg src = ra_alloc1(as, ir->op2, RSET_GPR);
    IRIns *irf = IR(ir->op1);
    Reg idx = ra_alloc1(as, irf->op1, rset_exclude(RSET_GPR, src));
    int32_t ofs = field_ofs[irf->op2];
    switch (irt_type(ir->t)) {
    case IRT_I8: case IRT_U8:
      emit_rxy(as, SO_STCY, src, 0, idx, ofs); break;
    case IRT_I16: case IRT_U16:
      emit_rxy(as, SO_STHY, src, 0, idx, ofs); break;
    default:
      if (irt_is64(ir->t))
	emit_rxy(as, SO_STG, src, 0, idx, ofs);
      else
	emit_rxy(as, SO_STY, src, 0, idx, ofs);
      break;
    }
  }
}

static void asm_xload(ASMState *as, IRIns *ir)
{
  Reg dest = ra_dest(as, ir, irt_isfp(ir->t) ? RSET_FPR : RSET_GPR);
  s390xOp op;
  if (irt_isfp(ir->t)) {
    op = irt_isnum(ir->t) ? SO_LDY : SO_LEY;
  } else {
    switch (irt_type(ir->t)) {
    case IRT_I8:  op = SO_LGB;  break;
    case IRT_U8:  op = SO_LLGC; break;
    case IRT_I16: op = SO_LGH;  break;
    case IRT_U16: op = SO_LLGH; break;
    default:
      op = irt_is64(ir->t) ? SO_LG : SO_LLGF;
      break;
    }
  }
  asm_fusexref(as, op, dest, ir->op1, RSET_GPR);
}

static void asm_xstore(ASMState *as, IRIns *ir)
{
  if (ir->r != RID_SINK) {
    Reg src = ra_alloc1(as, ir->op2,
			irt_isfp(ir->t) ? RSET_FPR : RSET_GPR);
    s390xOp op;
    if (irt_isfp(ir->t)) {
      op = irt_isnum(ir->t) ? SO_STDY : SO_STEY;
    } else {
      switch (irt_type(ir->t)) {
      case IRT_I8: case IRT_U8:
	op = SO_STCY; break;
      case IRT_I16: case IRT_U16:
	op = SO_STHY; break;
      default:
	op = irt_is64(ir->t) ? SO_STG : SO_STY;
	break;
      }
    }
    asm_fusexref(as, op, src, ir->op1, rset_exclude(RSET_GPR, src));
  }
}

static void asm_ahuvload(ASMState *as, IRIns *ir)
{
  Reg idx, tmp, dest = RID_NONE;
  int32_t ofs = 0;
  IRType1 t = ir->t;
  RegSet allow = RSET_GPR;
  lj_assertA(irt_isnum(ir->t) || irt_ispri(ir->t) || irt_isaddr(ir->t) ||
	     irt_isint(ir->t),
	     "bad load type %d", irt_type(ir->t));
  if (ra_used(ir)) {
    dest = ra_dest(as, ir, irt_isnum(t) ? RSET_FPR : allow);
    rset_clear(allow, dest);
  }
  tmp = (irt_isnum(t) || !ra_hasreg(dest)) ? ra_scratch(as, allow) : dest;
  rset_clear(allow, tmp);
  idx = asm_fuseahuref(as, ir->op1, &ofs, rset_clear(allow, tmp));
  rset_clear(allow, idx);
  if (ir->o == IR_VLOAD) ofs += 8 * ir->op2;
  if (ra_hasreg(dest)) {
    if (irt_isnum(t))
      emit_rre(as, SO_LDGR, dest, tmp);
    else if (irt_isaddr(t))
      emit_ril(as, SO_NIHF, dest, LJ_GCVMASK >> 32);
  }
  /* Always do the type check, even if the load result is unused. */
  if (irt_type(t) >= IRT_NUM) {
    lj_assertA(irt_isinteger(t) || irt_isnum(t),
	       "bad load type %d", irt_type(t));
    asm_guardcc(as, irt_isnum(t) ? CC_NL : CC_NE);
    emit_ril(as, SO_CLIH, tmp, (LJ_TISNUM << 15));
  } else {
    asm_guardcc(as, CC_NE);
    emit_ril(as, SO_CLFI, RID_TMP, (int32_t)irt_toitype(t));
    emit_rxy(as, SO_SRAG, RID_TMP, tmp, 0, 47);
  }
  emit_rxy(as, SO_LG, tmp, 0, idx, ofs);
}

static void asm_ahustore(ASMState *as, IRIns *ir)
{
  if (ir->r != RID_SINK) {
    RegSet allow = RSET_GPR;
    Reg idx;
    int32_t ofs = 0;
    if (irt_isnum(ir->t)) {
      Reg src = ra_alloc1(as, ir->op2, RSET_FPR);
      idx = asm_fuseahuref(as, ir->op1, &ofs, allow);
      if (S390F_U_OK(ofs, 12))
	emit_rx(as, SO_STD, src, 0, idx, (uint32_t)ofs);
      else
	emit_rxy(as, SO_STDY, src, 0, idx, ofs);
    } else {
      Reg src = RID_NONE, tmp;
      if (!irt_ispri(ir->t)) {
	src = ra_alloc1(as, ir->op2, allow);
	rset_clear(allow, src);
      }
      idx = asm_fuseahuref(as, ir->op1, &ofs, allow);
      rset_clear(allow, idx);
      tmp = ra_scratch(as, allow);
      emit_rxy(as, SO_STG, tmp, 0, idx, ofs);
      if (irt_ispri(ir->t)) {
	emit_loadu64(as, tmp, ~((uint64_t)~irt_toitype(ir->t) << 47));
      } else if (irt_isinteger(ir->t)) {
	emit_ril(as, SO_IIHF, tmp, (int32_t)irt_toitype(ir->t) << 15);
	emit_rr(as, SO_LR, tmp, src);
      } else {
	emit_ril(as, SO_OIHF, tmp, (int32_t)irt_toitype(ir->t) << 15);
	emit_rre(as, SO_LGR, tmp, src);
      }
    }
  }
}

static void asm_sload(ASMState *as, IRIns *ir)
{
  int32_t ofs = 8*((int32_t)ir->op1-2);
  IRType1 t = ir->t;
  Reg dest = RID_NONE, base;
  RegSet allow = RSET_GPR;
  lj_assertA(!(ir->op2 & IRSLOAD_PARENT),
	     "bad parent SLOAD");  /* Handled by asm_head_side(). */
  lj_assertA(irt_isguard(t) || !(ir->op2 & IRSLOAD_TYPECHECK),
	     "inconsistent SLOAD variant");
  if ((ir->op2 & IRSLOAD_CONVERT) && irt_isguard(t) && irt_isint(t)) {
    dest = ra_scratch(as, RSET_FPR);
    asm_tointg(as, ir, dest);
    t.irt = IRT_NUM;  /* Continue with a regular number type check. */
  } else if (ra_used(ir)) {
    Reg tmp = RID_NONE;
    if ((ir->op2 & IRSLOAD_CONVERT))
      tmp = ra_scratch(as, irt_isint(t) ? RSET_FPR : RSET_GPR);
    lj_assertA((irt_isnum(t)) || irt_isint(t) || irt_isaddr(t),
	       "bad SLOAD type %d", irt_type(t));
    dest = ra_dest(as, ir, irt_isnum(t) ? RSET_FPR : allow);
    base = ra_alloc1(as, REF_BASE, rset_clear(allow, dest));
    if (irt_isaddr(t)) {
      emit_ril(as, SO_NIHF, dest, LJ_GCVMASK >> 32);
    } else if ((ir->op2 & IRSLOAD_CONVERT)) {
      if (irt_isint(t)) {
	emit_rrf(as, SO_CFDBR, dest, tmp, 5);
	/* If value is already loaded for type check, move it to FPR. */
	if ((ir->op2 & IRSLOAD_TYPECHECK))
	  emit_rre(as, SO_LDGR, tmp, dest);
	else
	  dest = tmp;
	t.irt = IRT_NUM;  /* Check for original type. */
      } else {
	emit_rre(as, SO_CDFBR, dest, tmp);
	dest = tmp;
	t.irt = IRT_INT;  /* Check for original type. */
      }
    }
    goto dotypecheck;
  }
  base = ra_alloc1(as, REF_BASE, allow);
dotypecheck:
  rset_clear(allow, base);
  if ((ir->op2 & IRSLOAD_TYPECHECK)) {
    Reg tmp;
    if (ra_hasreg(dest) && rset_test(RSET_GPR, dest)) {
      tmp = dest;
    } else {
      tmp = ra_scratch(as, allow);
      if (ra_hasreg(dest))
	emit_rre(as, SO_LDGR, dest, tmp);
    }
    rset_clear(allow, tmp);
    /* Need type check, even if the load result is unused. */
    asm_guardcc(as, irt_isnum(t) ? CC_NL : CC_NE);
    if (irt_type(t) >= IRT_NUM) {
      lj_assertA(irt_isinteger(t) || irt_isnum(t),
		 "bad SLOAD type %d", irt_type(t));
      emit_ril(as, SO_CLIH, tmp, (ir->op2 & IRSLOAD_KEYINDEX) ?
	       LJ_KEYINDEX : (LJ_TISNUM << 15));
    } else if (irt_ispri(t)) {
      emit_ril(as, SO_CLIH, tmp, ~(~irt_toitype(t) << 15));
    } else {
      emit_ril(as, SO_CLFI, RID_TMP, irt_toitype(t));
      emit_rxy(as, SO_SRAG, RID_TMP, tmp, 0, 47);
    }
    emit_rxy(as, SO_LG, tmp, 0, base, ofs);
    return;
  }
  if (ra_hasreg(dest)) {
    if (irt_isnum(t)) {
      if (S390F_U_OK(ofs, 12))
	emit_rx(as, SO_LD, dest, 0, base, (uint32_t)ofs);
      else
	emit_rxy(as, SO_LDY, dest, 0, base, ofs);
    } else if (irt_isint(t)) {
      emit_rxy(as, SO_LLGF, dest, 0, base, ofs + 4);
    } else {
      emit_rxy(as, SO_LG, dest, 0, base, ofs);
    }
  }
}

/* -- Allocations --------------------------------------------------------- */

#if LJ_HASFFI
static void asm_cnew(ASMState *as, IRIns *ir)
{
  CTState *cts = ctype_ctsG(J2G(as->J));
  CTypeID id = (CTypeID)IR(ir->op1)->i;
  CTSize sz;
  CTInfo info = lj_ctype_info(cts, id, &sz);
  const CCallInfo *ci = &lj_ir_callinfo[IRCALL_lj_mem_newgco];
  IRRef args[4];
  RegSet allow = (RSET_GPR & ~RSET_SCRATCH);
  lj_assertA(sz != CTSIZE_INVALID || (ir->o == IR_CNEW && ir->op2 != REF_NIL),
	     "bad CNEW/CNEWI operands");

  as->gcsteps++;
  asm_setupresult(as, ir, ci);  /* GCcdata * */
  /* Initialize immutable cdata object. */
  if (ir->o == IR_CNEWI) {
    int32_t ofs = (int32_t)sizeof(GCcdata);
    Reg r = ra_alloc1(as, ir->op2, allow);
    lj_assertA(sz == 4 || sz == 8, "bad CNEWI size %d", sz);
    emit_rxy(as, sz == 8 ? SO_STG : SO_STY, r, 0, RID_RET, ofs);
  } else if (ir->op2 != REF_NIL) {  /* Create VLA/VLS/aligned cdata. */
    ci = &lj_ir_callinfo[IRCALL_lj_cdata_newv];
    args[0] = ASMREF_L;     /* lua_State *L */
    args[1] = ir->op1;      /* CTypeID id   */
    args[2] = ir->op2;      /* CTSize sz    */
    args[3] = ASMREF_TMP1;  /* CTSize align */
    asm_gencall(as, ci, args);
    emit_loadi(as, ra_releasetmp(as, ASMREF_TMP1), (int32_t)ctype_align(info));
    return;
  }

  /* Initialize gct and ctypeid. lj_mem_newgco() already sets marked. */
  {
    Reg tmp = ra_scratch(as, allow);
    emit_rxy(as, SO_STCY, tmp, 0, RID_RET, (int32_t)offsetof(GCcdata, gct));
    emit_loadi(as, tmp, (int32_t)(~LJ_TCDATA));
    if (id != 0) {
      Reg r = ra_allock(as, (int32_t)id, allow);
      emit_rxy(as, SO_STHY, r, 0, RID_RET,
	       (int32_t)offsetof(GCcdata, ctypeid));
    } else {
      emit_rxy(as, SO_STHY, tmp, 0, RID_RET,
	       (int32_t)offsetof(GCcdata, ctypeid));
      emit_loadi(as, tmp, 0);
    }
  }
  args[0] = ASMREF_L;     /* lua_State *L */
  args[1] = ASMREF_TMP1;  /* MSize size   */
  asm_gencall(as, ci, args);
  ra_allockreg(as, (int32_t)(sz+sizeof(GCcdata)),
	       ra_releasetmp(as, ASMREF_TMP1));
}
#endif

/* -- Write barriers ------------------------------------------------------ */

static void asm_tbar(ASMState *as, IRIns *ir)
{
  Reg tab = ra_alloc1(as, ir->op1, RSET_GPR);
  Reg mark = ra_scratch(as, rset_exclude(RSET_GPR, tab));
  Reg link = ra_scratch(as, rset_exclude(rset_exclude(RSET_GPR, tab), mark));
  MCLabel l_end = emit_label(as);
  emit_rxy(as, SO_STCY, mark, 0, tab, (int32_t)offsetof(GCtab, marked));
  emit_ri(as, SO_NILL, mark, ~LJ_GC_BLACK);
  emit_rxy(as, SO_STG, link, 0, tab, (int32_t)offsetof(GCtab, gclist));
  emit_setgl(as, tab, gc.grayagain);
  emit_getgl(as, link, gc.grayagain);
  emit_cond_branch(as, CC_E, l_end);
  emit_ri(as, SO_TMLL, mark, LJ_GC_BLACK);
  emit_rxy(as, SO_LLGC, mark, 0, tab, (int32_t)offsetof(GCtab, marked));
}

static void asm_obar(ASMState *as, IRIns *ir)
{
  const CCallInfo *ci = &lj_ir_callinfo[IRCALL_lj_gc_barrieruv];
  IRRef args[2];
  MCLabel l_end;
  Reg obj, val, tmp;
  /* No need for other object barriers (yet). */
  lj_assertA(IR(ir->op1)->o == IR_UREFC, "bad OBAR type");
  ra_evictset(as, RSET_SCRATCH);
  l_end = emit_label(as);
  args[0] = ASMREF_TMP1;  /* global_State *g */
  args[1] = ir->op1;      /* TValue *tv      */
  asm_gencall(as, ci, args);
  emit_rre(as, SO_LGR, ra_releasetmp(as, ASMREF_TMP1), RID_JGL);
  obj = IR(ir->op1)->r;
  tmp = ra_scratch(as, rset_exclude(RSET_GPR, obj));
  emit_cond_branch(as, CC_E, l_end);
  emit_ri(as, SO_TMLL, tmp, (int16_t)LJ_GC_BLACK);
  emit_rxy(as, SO_LLGC, tmp, 0, obj,
	   (int32_t)offsetof(GCupval, marked)-(int32_t)offsetof(GCupval, tv));
  emit_cond_branch(as, CC_E, l_end);
  emit_ri(as, SO_TMLL, RID_TMP, (int16_t)LJ_GC_WHITES);
  val = ra_alloc1(as, ir->op2, rset_exclude(RSET_GPR, obj));
  emit_rxy(as, SO_LLGC, RID_TMP, 0, val, (int32_t)offsetof(GChead, marked));
}

/* -- Arithmetic and logic operations ------------------------------------- */

/* FP arithmetic is two-operand only: dest = dest op right. */
static void asm_fparith(ASMState *as, IRIns *ir, s390xOp ai)
{
  Reg dest = ra_dest(as, ir, RSET_FPR);
  Reg right, left = ra_alloc2(as, ir, RSET_FPR);
  right = (left >> 8); left &= 255;
  if (dest == right && dest != left) {
    if (ai == SO_ADBR || ai == SO_MDBR) {  /* Commutative: swap operands. */
      Reg tmp = left; left = right; right = tmp;
    } else {  /* Non-commutative: need a temporary. */
      Reg tmp = ra_scratch(as,
			   rset_exclude(rset_exclude(RSET_FPR, left), dest));
      emit_rre(as, ai, dest, tmp);
      emit_rr(as, SO_LDR, dest, left);
      emit_rr(as, SO_LDR, tmp, right);
      return;
    }
  }
  emit_rre(as, ai, dest, right);
  if (dest != left)
    emit_rr(as, SO_LDR, dest, left);
}

static void asm_fpunary(ASMState *as, IRIns *ir, s390xOp ai)
{
  Reg dest = ra_dest(as, ir, RSET_FPR);
  Reg left = ra_hintalloc(as, ir->op1, dest, RSET_FPR);
  emit_rre(as, ai, dest, left);
}

static void asm_fpmath(ASMState *as, IRIns *ir)
{
  IRFPMathOp fpm = (IRFPMathOp)ir->op2;
  if (fpm == IRFPM_SQRT) {
    asm_fpunary(as, ir, SO_SQDBR);
  } else if (fpm <= IRFPM_TRUNC) {
    /* FIDBR rounding modes for floor, ceil and trunc. */
    static const uint8_t fidbr_rm[] = { 7, 6, 5 };
    Reg dest = ra_dest(as, ir, RSET_FPR);
    Reg left = ra_hintalloc(as, ir->op1, dest, RSET_FPR);
    emit_rrf(as, SO_FIDBR, dest, left, fidbr_rm[fpm]);
  } else {
    asm_callid(as, ir, IRCALL_lj_vm_floor + fpm);
  }
}

static void asm_intop(ASMState *as, IRIns *ir, s390xOp op2, s390xOp op3)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
  Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_GPR, left));
  if (op2 != SO_SGR && op2 != SO_SR && dest == right && dest != left) {
    Reg tmp = left; left = right; right = tmp;
  }
  if (dest == left) {
    if (op2 < SO_LDR)
      emit_rr(as, op2, dest, right);
    else
      emit_rre(as, op2, dest, right);
  } else {
    emit_rrf(as, op3, dest, left, right);
  }
}

static void asm_add(ASMState *as, IRIns *ir)
{
  int32_t k;
  if (irt_isnum(ir->t)) {
    asm_fparith(as, ir, SO_ADBR);
  } else {
    if (irt_isguard(ir->t)) asm_guardcc(as, CC_O);
    if (asm_isk32(as, ir->op2, &k)) {
      Reg dest = ra_dest(as, ir, RSET_GPR);
      Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
      if (checki16(k)) {
	if (dest == left)
	  emit_ri(as, irt_is64(ir->t) ? SO_AGHI : SO_AHI, dest, k);
	else
	  emit_riec(as, irt_is64(ir->t) ? SO_AGHIK : SO_AHIK, dest, left, k, 0);
      } else {
	emit_ril(as, irt_is64(ir->t) ? SO_AGFI : SO_AFI, dest, k);
	if (dest != left)
	  emit_rre(as, SO_LGR, dest, left);
      }
    } else if (irt_is64(ir->t)) {
      asm_intop(as, ir, SO_AGR, SO_AGRK);
    } else {
      asm_intop(as, ir, SO_AR, SO_ARK);
    }
  }
}

static void asm_sub(ASMState *as, IRIns *ir)
{
  if (irt_isnum(ir->t)) {
    asm_fparith(as, ir, SO_SDBR);
  } else {
    if (irt_isguard(ir->t)) asm_guardcc(as, CC_O);
    if (irt_is64(ir->t)) {
      asm_intop(as, ir, SO_SGR, SO_SGRK);
    } else {
      asm_intop(as, ir, SO_SR, SO_SRK);
    }
  }
}

static void asm_mul(ASMState *as, IRIns *ir)
{
  int32_t k;
  if (irt_isnum(ir->t)) {
    asm_fparith(as, ir, SO_MDBR);
  } else {
    Reg dest = ra_dest(as, ir, RSET_GPR);
    Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
    if (asm_isk32(as, ir->op2, &k)) {
      if (!irt_is64(ir->t) && irt_isguard(ir->t)) {
	asm_guardcc(as, CC_NE);
	emit_rre(as, SO_CGFR, dest, dest);
	emit_ril(as, SO_MSGFI, dest, k);
	emit_rre(as, SO_LGFR, dest, left);
	return;
      } else {
	emit_ril(as, irt_is64(ir->t) ? SO_MSGFI : SO_MSFI, dest, k);
      }
    } else {
      Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_GPR, left));
      if (dest == right && dest != left) {
	Reg tmp = left; left = right; right = tmp;
      }
      if (irt_is64(ir->t)) {
	emit_rre(as, SO_MSGR, dest, right);
      } else if (irt_isguard(ir->t)) {
	/* Check that the 64 bit product fits into 32 bits. */
	asm_guardcc(as, CC_NE);
	emit_rre(as, SO_CGFR, dest, dest);
	emit_rre(as, SO_MSGFR, dest, right);
	emit_rre(as, SO_LGFR, dest, left);
	return;
      } else {
	emit_rre(as, SO_MSR, dest, right);
      }
    }
    if (dest != left)
      emit_rre(as, SO_LGR, dest, left);
  }
}

#define asm_addov(as, ir)	asm_add(as, ir)
#define asm_subov(as, ir)	asm_sub(as, ir)
#define asm_mulov(as, ir)	asm_mul(as, ir)

#define asm_fpdiv(as, ir)	asm_fparith(as, ir, SO_DDBR)
#define asm_abs(as, ir)		asm_fpunary(as, ir, SO_LPDBR)

static void asm_neg(ASMState *as, IRIns *ir)
{
  if (irt_isnum(ir->t)) {
    asm_fpunary(as, ir, SO_LCDBR);
  } else {
    Reg dest = ra_dest(as, ir, RSET_GPR);
    Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
    if (irt_is64(ir->t))
      emit_rre(as, SO_LCGR, dest, left);
    else
      emit_rr(as, SO_LCR, dest, left);
  }
}

/* Try to emit AND/OR/XOR with a 32 bit immediate operand. */
static int asm_bitop_imm(ASMState *as, IRIns *ir, s390xOp low_op,
			 int one_is_neutral)
{
  IRRef lref = ir->op1, rref = ir->op2;
  int32_t k;
  if (irref_isk(lref) && !irref_isk(rref)) {
    IRRef tmp = lref; lref = rref; rref = tmp;
  }
  if (irref_isk(rref) && asm_isk32(as, rref, &k) &&
      (!irt_is64(ir->t) || (k < 0) == one_is_neutral)) {
    Reg dest = ra_dest(as, ir, RSET_GPR);
    Reg left = ra_hintalloc(as, lref, dest, RSET_GPR);
    emit_ril(as, low_op, dest, k);
    if (dest != left)
      emit_rre(as, SO_LGR, dest, left);
    return 1;
  }
  return 0;
}

static void asm_band(ASMState *as, IRIns *ir)
{
  if (asm_bitop_imm(as, ir, SO_NILF, 1)) return;
  asm_intop(as, ir, SO_NGR, SO_NGRK);
}

static void asm_bor(ASMState *as, IRIns *ir)
{
  if (asm_bitop_imm(as, ir, SO_OILF, 0)) return;
  asm_intop(as, ir, SO_OGR, SO_OGRK);
}

static void asm_bxor(ASMState *as, IRIns *ir)
{
  if (asm_bitop_imm(as, ir, SO_XILF, 0)) return;
  asm_intop(as, ir, SO_XGR, SO_XGRK);
}

static void asm_bnot(ASMState *as, IRIns *ir)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
  if (irt_is64(ir->t))
    emit_ril(as, SO_XIHF, dest, (int32_t)0xffffffff);
  emit_ril(as, SO_XILF, dest, (int32_t)0xffffffff);
  if (dest != left)
    emit_rre(as, SO_LGR, dest, left);
}

static void asm_bswap(ASMState *as, IRIns *ir)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  Reg left = ra_alloc1(as, ir->op1, RSET_GPR);
  emit_rre(as, irt_is64(ir->t) ? SO_LRVGR : SO_LRVR, dest, left);
}

/* RSY-a shifts are encoded like RXY, with R3 in the x2 field. */
static void asm_bitshift(ASMState *as, IRIns *ir, s390xOp ai64, s390xOp ai32)
{
  Reg dest = ra_dest(as, ir, RSET_GPR);
  Reg left = ra_alloc1(as, ir->op1, RSET_GPR);
  s390xOp ai = irt_is64(ir->t) ? ai64 : ai32;
  if (irref_isk(ir->op2)) {  /* Constant shifts. */
    int32_t shift = IR(ir->op2)->i & (irt_is64(ir->t) ? 63 : 31);
    emit_rxy(as, ai, dest, left, 0, shift);
  } else {  /* Variable-length shifts. */
    Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_GPR, left));
    emit_rxy(as, ai, dest, left, right, 0);
  }
}

#define asm_bshl(as, ir)	asm_bitshift(as, ir, SO_SLLG, SO_SLLK)
#define asm_bshr(as, ir)	asm_bitshift(as, ir, SO_SRLG, SO_SRLK)
#define asm_bsar(as, ir)	asm_bitshift(as, ir, SO_SRAG, SO_SRAK)
#define asm_bror(as, ir)	lj_assertA(0, "unexpected BROR")
#define asm_brol(as, ir)	asm_bitshift(as, ir, SO_RLLG, SO_RLL)

/* cc and fcc are the conditions for replacing the result with right. */
static void asm_min_max(ASMState *as, IRIns *ir, s390xCC cc, s390xCC fcc)
{
  if (irt_isnum(ir->t)) {
    Reg dest = ra_dest(as, ir, RSET_FPR);
    Reg left = ra_alloc1(as, ir->op1, RSET_FPR);
    Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_FPR, left));
    int skipcc = fcc ^ CC_UNCOND;
    emit_rr(as, SO_LDR, dest, right);
    emit_ri(as, SO_BRC, skipcc, 3);  /* Skip LDR. */
    emit_rre(as, SO_CDBR, left, right);
    if (dest != left)
      emit_rr(as, SO_LDR, dest, left);
  } else {
    Reg dest = ra_dest(as, ir, RSET_GPR);
    Reg left = ra_hintalloc(as, ir->op1, dest, RSET_GPR);
    Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_GPR, left));
    if (irt_is64(ir->t)) {
      emit_rrf(as, SO_LOCGR, dest, right, cc);
      emit_rre(as, SO_CGR, dest, right);
    } else {
      emit_rrf(as, SO_LOCR, dest, right, cc);
      emit_rr(as, SO_CR, dest, right);
    }
    if (dest != left)
      emit_rre(as, SO_LGR, dest, left);
  }
}

#define asm_min(as, ir)		asm_min_max(as, ir, CC_H, CC_H)
#define asm_max(as, ir)		asm_min_max(as, ir, CC_L, CC_L)

/* -- Comparisons --------------------------------------------------------- */

/* Map of comparisons to inverted condition masks. ORDER IR. */
static const uint8_t asm_compmap[IR_ABC+1] = {
  /* op     int cc   FP cc */
  /* LT  */ CC_HE + (CC_NL << 4),
  /* GE  */ CC_L  + (CC_NHE << 4),
  /* LE  */ CC_H  + (CC_NLE << 4),
  /* GT  */ CC_LE + (CC_NH << 4),
  /* ULT */ CC_HE + (CC_HE << 4),
  /* UGE */ CC_L  + (CC_L << 4),
  /* ULE */ CC_H  + (CC_H << 4),
  /* UGT */ CC_LE + (CC_LE << 4),
  /* EQ  */ CC_LH + (CC_NE << 4),
  /* NE  */ CC_E  + (CC_E << 4),
  /* ABC */ CC_LE + (CC_LE << 4)  /* Same as UGT. */
};

/* FP comparisons. */
static void asm_fpcomp(ASMState *as, IRIns *ir)
{
  uint8_t cc = asm_compmap[ir->o] >> 4;
  Reg left = ra_alloc1(as, ir->op1, RSET_FPR);
  Reg right = ra_alloc1(as, ir->op2, rset_exclude(RSET_FPR, left));
  asm_guardcc(as, cc);
  emit_rre(as, SO_CDBR, left, right);
}

/* Integer comparisons. */
static void asm_intcomp(ASMState *as, IRIns *ir)
{
  uint8_t cc = asm_compmap[ir->o] & 0x0f;
  IRRef lref = ir->op1, rref = ir->op2;
  int is_unsigned = (ir->o >= IR_ULT && ir->o <= IR_UGT) || ir->o == IR_ABC;
  int32_t k;
  if (irref_isk(rref) && asm_isk32(as, rref, &k)) {
    Reg left = ra_alloc1(as, lref, RSET_GPR);
    asm_guardcc(as, cc);
    if (is_unsigned)
      emit_ril(as, irt_is64(ir->t) ? SO_CLGFI : SO_CLFI, left, k);
    else
      emit_ril(as, irt_is64(ir->t) ? SO_CGFI : SO_CFI, left, k);
  } else if (irref_isk(lref) && asm_isk32(as, lref, &k)) {
    /* Swap operands, i.e. swap the L and H bits of the condition mask. */
    uint8_t scc = (uint8_t)((cc & 0x9) | ((cc & 0x4) >> 1) | ((cc & 0x2) << 1));
    Reg right = ra_alloc1(as, rref, RSET_GPR);
    asm_guardcc(as, scc);
    if (is_unsigned)
      emit_ril(as, irt_is64(ir->t) ? SO_CLGFI : SO_CLFI, right, k);
    else
      emit_ril(as, irt_is64(ir->t) ? SO_CGFI : SO_CFI, right, k);
  } else {
    Reg left = ra_alloc1(as, lref, RSET_GPR);
    Reg right = ra_alloc1(as, rref, rset_exclude(RSET_GPR, left));
    asm_guardcc(as, cc);
    if (is_unsigned) {
      if (irt_is64(ir->t))
	emit_rre(as, SO_CLGR, left, right);
      else
	emit_rr(as, SO_CLR, left, right);
    } else {
      if (irt_is64(ir->t))
	emit_rre(as, SO_CGR, left, right);
      else
	emit_rr(as, SO_CR, left, right);
    }
  }
}

static void asm_comp(ASMState *as, IRIns *ir)
{
  if (irt_isnum(ir->t))
    asm_fpcomp(as, ir);
  else
    asm_intcomp(as, ir);
}

#define asm_equal(as, ir)	asm_comp(as, ir)

/* -- Split register ops -------------------------------------------------- */

/* Hiword op of a split 64/64 bit op. Previous op is the loword op. */
static void asm_hiop(ASMState *as, IRIns *ir)
{
  /* HIOP is marked as a store because it needs its own DCE logic. */
  int uselo = ra_used(ir-1), usehi = ra_used(ir);  /* Loword/hiword used? */
  if (LJ_UNLIKELY(!(as->flags & JIT_F_OPT_DCE))) uselo = usehi = 1;
  if (!usehi) return;  /* Skip unused hiword op for all remaining ops. */
  switch ((ir-1)->o) {
  case IR_CALLN:
  case IR_CALLL:
  case IR_CALLS:
  case IR_CALLXS:
    if (!uselo)
      ra_allocref(as, ir->op1, RID2RSET(RID_RETLO));  /* Mark lo op as used. */
    break;
  default: lj_assertA(0, "bad HIOP for op %d", (ir-1)->o); break;
  }
}

/* -- Profiling ----------------------------------------------------------- */

static void asm_prof(ASMState *as, IRIns *ir)
{
  UNUSED(as); UNUSED(ir);
  __builtin_trap();
}

/* -- Stack handling ------------------------------------------------------ */

/* Check Lua stack size for overflow. Use exit handler as fallback. */
static void asm_stack_check(ASMState *as, BCReg topslot,
			    IRIns *irp, RegSet allow, ExitNo exitno)
{
  Reg pbase = RID_BASE;
  int needload = 0;
  if (irp) {
    pbase = irp->r;
    if (!ra_hasreg(pbase)) {
      pbase = allow ? rset_pickbot(allow) : RID_RET;
      needload = 1;
    }
  }
  emit_cond_branch(as, CC_L, asm_exitstub_addr(as, exitno));
  emit_ril(as, SO_CLGFI, RID_TMP, (int32_t)(8*(int32_t)topslot));
  emit_rre(as, SO_SGR, RID_TMP, pbase);
  emit_rxy(as, SO_LG, RID_TMP, 0, RID_TMP,
	   (int32_t)offsetof(lua_State, maxstack));
  if (needload) {
    if (!allow)  /* Restore temp register. */
      emit_rxy(as, SO_LG, pbase, 0, RID_SP, 0);
    else
      ra_modified(as, pbase);
    emit_getgl(as, pbase, jit_base);
    if (!allow)  /* Save temp register. */
      emit_rxy(as, SO_STG, pbase, 0, RID_SP, 0);
  }
  emit_getgl(as, RID_TMP, cur_L);
  /* The stack check of a side trace runs before the vmstate update in
  ** asm_head_side(), but its exit number refers to this trace.
  */
  if (irp)
    emit_setvmstate(as, (int32_t)as->T->traceno);
}

/* Restore Lua stack from on-trace state. */
static void asm_stack_restore(ASMState *as, SnapShot *snap)
{
  SnapEntry *map = &as->T->snapmap[snap->mapofs];
#ifdef LUA_USE_ASSERT
  SnapEntry *flinks = &as->T->snapmap[snap_nextofs(as->T, snap)-1-LJ_FR2];
#endif
  MSize n, nent = snap->nent;
  /* Store the value of all modified slots to the Lua stack. */
  for (n = 0; n < nent; n++) {
    SnapEntry sn = map[n];
    BCReg s = snap_slot(sn);
    int32_t ofs = 8*((int32_t)s-1-LJ_FR2);
    IRRef ref = snap_ref(sn);
    IRIns *ir = IR(ref);
    if ((sn & SNAP_NORESTORE))
      continue;
    if ((sn & SNAP_KEYINDEX)) {
      RegSet allow = rset_exclude(RSET_GPR, RID_BASE);
      Reg r = irref_isk(ref) ? ra_allock(as, ir->i, allow) :
			       ra_alloc1(as, ref, allow);
      rset_clear(allow, r);
      emit_rxy(as, SO_STY, r, 0, RID_BASE, ofs+4);
      emit_rxy(as, SO_STY, ra_allock(as, LJ_KEYINDEX, allow), 0, RID_BASE, ofs);
    } else if (irt_isnum(ir->t)) {
      Reg src = ra_alloc1(as, ref, RSET_FPR);
      if (S390F_U_OK(ofs, 12))
	emit_rx(as, SO_STD, src, 0, RID_BASE, (uint32_t)ofs);
      else
	emit_rxy(as, SO_STDY, src, 0, RID_BASE, ofs);
    } else {
      asm_tvstore64(as, RID_BASE, ofs, ref);
    }
    checkmclim(as);
  }
  lj_assertA(map + nent == flinks, "inconsistent frames in snapshot");
}

/* -- GC handling --------------------------------------------------------- */

/* Marker to prevent patching the GC check exit. */
#define S390X_NOPATCH_GC_CHECK	0x1855u  /* lr r5, r5 */

/* Check GC threshold and do one or more GC steps. */
static void asm_gc_check(ASMState *as)
{
  const CCallInfo *ci = &lj_ir_callinfo[IRCALL_lj_gc_step_jit];
  IRRef args[2];
  MCLabel l_end;
  Reg tmp2;
  ra_evictset(as, RSET_SCRATCH);
  l_end = emit_label(as);
  /* Exit trace if in GCSatomic or GCSfinalize. Avoids syncing GC objects. */
  asm_guardcc(as, CC_NE);  /* Assumes asm_snap_prep() is done. */
  *--as->mcp = S390X_NOPATCH_GC_CHECK;
  emit_ril(as, SO_CLFI, RID_RET, 0);
  args[0] = ASMREF_TMP1;  /* global_State *g */
  args[1] = ASMREF_TMP2;  /* MSize steps     */
  asm_gencall(as, ci, args);
  emit_rre(as, SO_LGR, ra_releasetmp(as, ASMREF_TMP1), RID_JGL);
  tmp2 = ra_releasetmp(as, ASMREF_TMP2);
  emit_loadi(as, tmp2, as->gcsteps);
  /* Jump around GC step if GC total < GC threshold. */
  emit_cond_branch(as, CC_L, l_end);
  emit_rre(as, SO_CLGR, RID_R0, tmp2);
  emit_getgl(as, tmp2, gc.threshold);
  emit_getgl(as, RID_R0, gc.total);
  as->gcsteps = 0;
  checkmclim(as);
}

/* -- Loop handling ------------------------------------------------------- */

/* Fixup the loop branch. */
static void asm_loop_fixup(ASMState *as)
{
  MCode *p = as->mctop;
  MCode *target = as->mcp;
  if (as->loopinv) {  /* Inverted loop branch? */
    intptr_t delta = target - (p - 6);
    /* asm_guardcc already inverted the brcl and patched the final brcl. */
    p[-5] = delta >> 16;
    p[-4] = delta;
  } else {
    emit_brcl_at(p - 3, CC_UNCOND, target);
  }
}

/* Fixup the tail of the loop. */
static void asm_loop_tail_fixup(ASMState *as)
{
  UNUSED(as);  /* Nothing to do. */
}

/* -- Head of trace ------------------------------------------------------- */

/* Coalesce BASE register for a root trace. */
static void asm_head_root_base(ASMState *as)
{
  IRIns *ir = IR(REF_BASE);
  Reg r = ir->r;
  if (ra_hasreg(r)) {
    ra_free(as, r);
    if (rset_test(as->modset, r) || irt_ismarked(ir->t))
      ir->r = RID_INIT;  /* No inheritance for modified BASE register. */
    if (r != RID_BASE)
      emit_movrr(as, ir, r, RID_BASE);
  }
}

/* Coalesce BASE register for a side trace. */
static Reg asm_head_side_base(ASMState *as, IRIns *irp)
{
  IRIns *ir = IR(REF_BASE);
  Reg r = ir->r;
  if (ra_hasreg(r)) {
    ra_free(as, r);
    if (rset_test(as->modset, r) || irt_ismarked(ir->t))
      ir->r = RID_INIT;  /* No inheritance for modified BASE register. */
    if (irp->r == r) {
      return r;  /* Same BASE register already coalesced. */
    } else if (ra_hasreg(irp->r) && rset_test(as->freeset, irp->r)) {
      /* Move from coalesced parent reg. */
      emit_movrr(as, ir, r, irp->r);
      return irp->r;
    } else {
      emit_getgl(as, r, jit_base);  /* Otherwise reload BASE. */
    }
  }
  return RID_NONE;
}

/* -- Tail of trace ------------------------------------------------------- */

/* Fixup the tail code. */
static void asm_tail_fixup(ASMState *as, TraceNo lnk)
{
  MCode *mcp = as->mctail;
  MCode *target;
  /* Undo the sp adjustment in BC_JLOOP when exiting to the interpreter. */
  int32_t spadj = as->T->spadjust + (lnk ? 0 : sps_scale(SPS_FIXED));
  if (spadj) {  /* Emit stack adjustment. */
    if (checki16(spadj)) {
      *mcp++ = SO_AGHI | (RID_SP << 4);
      *mcp++ = spadj;
    } else {
      *mcp++ = SO_AGFI | (RID_SP << 4);
      *mcp++ = spadj >> 16;
      *mcp++ = spadj;
    }
  }
  /* Emit exit branch. */
  target = lnk ? traceref(as->J, lnk)->mcode :
		 (MCode *)(void *)lj_vm_exit_interp;
  if (lnk || brcl_reachable(mcp, target)) {
    emit_brcl_at(mcp, CC_UNCOND, target);
    mcp += 3;
  } else {
    int32_t disp = glofs(as, &as->J->k64[LJ_K64_VM_EXIT_INTERP]);
    *mcp++ = (SO_LG & 0xff00) | (RID_R1 << 4);
    *mcp++ = (disp & 0xfff) | (RID_JGL << 12);
    *mcp++ = ((disp >> 4) & 0xff00) | (SO_LG & 0xff);
    *mcp++ = SO_BCR | (CC_UNCOND << 4) | RID_R1;
  }
  while (as->mctop > mcp) *--as->mctop = SO_NOPR;
}

/* Prepare tail of code. */
static void asm_tail_prep(ASMState *as, TraceNo lnk)
{
  UNUSED(lnk);
  if (as->loopref) {
    as->invmcp = as->mcp = as->mctop - 3;  /* Leave room for brcl. */
  } else {
    /* Leave room for stack pointer adjustment and exit branch. */
    as->mcp = as->mctop - 6;
    as->invmcp = NULL;
  }
  as->mctail = as->mcp;
}

/* -- Trace setup --------------------------------------------------------- */

/* Ensure there are enough stack slots for call arguments. */
static Reg asm_setup_call_slots(ASMState *as, IRIns *ir, const CCallInfo *ci)
{
#if LJ_HASFFI
  uint32_t i, nargs = CCI_XNARGS(ci);
  if (nargs > (uint32_t)(REGARG_NUMGPR < REGARG_NUMFPR ?
			 REGARG_NUMGPR : REGARG_NUMFPR)) {
    IRRef args[CCI_NARGS_MAX*2];
    int ngpr = REGARG_NUMGPR, nfpr = REGARG_NUMFPR;
    int nslots = 40;  /* Skip register save area. */
    asm_collectargs(as, ir, ci, args);
    for (i = 0; i < nargs; i++) {
      if (args[i] && irt_isfp(IR(args[i])->t)) {
	if (nfpr > 0) { nfpr--; continue; }
      } else {
	if (ngpr > 0) { ngpr--; continue; }
      }
      nslots += 2;
    }
    if (nslots > as->evenspill)  /* Leave room for args in stack slots. */
      as->evenspill = nslots;
  }
#endif
  UNUSED(as);
  return REGSP_HINT(irt_isfp(ir->t) ? RID_FPRET : RID_RET);
}

static void asm_setup_target(ASMState *as)
{
  /* May need extra exit for asm_stack_check on side traces. */
  asm_exitstub_setup(as, as->T->nsnap + (as->parent ? 1 : 0));
}

/* -- Trace patching ------------------------------------------------------ */

/* Return instruction length in halfwords. */
static int asm_s390_insnlen(uint32_t op)
{
  return ((op+0x4000) >> 15) + 1;
}

/* Patch exit jumps of existing machine code to a new target. */
void lj_asm_patchexit(jit_State *J, GCtrace *T, ExitNo exitno, MCode *target)
{
  MCode *p = T->mcode;
  MCode *pe = (MCode *)((char *)p + T->szmcode);
  MCode *cstart = NULL;
  MCode *mcarea = lj_mcode_patch(J, p, 0);
  MCode *px = exitstub_trace_addr(T, exitno);
  for (; p < pe; p += asm_s390_insnlen(p[0])) {
    /* Look for exitstub branch, replace with branch to target. */
    if ((p[0] & 0xff0f) == SO_BRCL) {
      intptr_t delta = (int32_t)(((uint32_t)p[1] << 16) | p[2]);
      if (p + delta == px) {
	if (p >= T->mcode + 1 && p[-1] == S390X_NOPATCH_GC_CHECK)
	  continue;
	delta = target - p;
	p[1] = delta >> 16;
	p[2] = delta;
	if (!cstart) cstart = p;
      }
    }
  }
  /* All guards use brcl, so the exit stubs never need to be patched. */
  if (cstart)
    lj_mcode_sync(cstart, pe);
  lj_mcode_patch(J, mcarea, 1);
}
