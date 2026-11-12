----------------------------------------------------------------------------
-- LuaJIT s390x disassembler module.
--
-- Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
--
-- Contributed by Andreas Arnez, IBM Corp.
----------------------------------------------------------------------------
-- This is a helper module used by the LuaJIT machine code dumper module.
--
-- Apart from vector instructions, all z/Architecture instructions listed
-- in the Principles of Operation are supported.
------------------------------------------------------------------------------

local type = type
local sub, byte, format = string.sub, string.byte, string.format
local match, gmatch, gsub = string.match, string.gmatch, string.gsub
local rep = string.rep

-- Format letter -> bit size.
local map_fmtsz = {
  -- unsigned immediates
  m = 4, u = 8, o = 12, k = 16, i = 32,
  -- signed immediates
  U = 8, K = 16, I = 32,
  -- registers
  a = 4, B = 4, X = 4, W = 4, c = 4, f = 4, r = 4, v = 4,
  -- address displacements
  D = 12, E = 20,
  -- full addresses
  x = 20, s = 16, y = 28, t = 24, n = 24,
  -- lengths
  l = 4, L = 8,
  -- PC-relative offsets
  j = 12, J = 16, p = 24, P = 32,
  -- skip a number of bits
  ["."] = -4, ["-"] = -8, ["="] = -16,
}

local map_cc_suffix = {
  [0]="nop", "o", "h", "nle", "l", "nhe", "lh", "ne",
  "e", "nlh", "he", "nl", "le", "nh", "no", "",
}

local function cc1(pat, off, pat_uncond, pat_nop)
  return setmetatable({ off = off, nbits = 4 }, {
    __index = function(t, m)
      pat_nop = pat_nop or pat_uncond
      if m == 0 and pat_nop then return pat_nop end
      if m == 15 and pat_uncond then return pat_uncond end
      return format(pat, map_cc_suffix[m])
    end
  })
end

local map_cmp_suffix = {
  [2]="h", [4]="l", [6]="ne", [8]="e", [10]="nl", [12]="nh"
}

local function cc2(pat, off, generic_pat)
  return setmetatable({ off = off, nbits = 4 }, {
    __index = function(t, m)
      local s = map_cmp_suffix[m]
      return s and format(pat, s) or generic_pat
    end
  })
end

-- All instructions.
local map_insn = {
  [0]=nil,nil,nil,nil,"spm-r","balr-rr","bctr-rr",
  cc1("b%sr-.r",8,"br-.r","nopr-.r"),
  nil,nil,"svc-u","bsm-rr","bassm-rr","basr-rr","mvcl-rr","clcl-rr",
  "lpr-rr","lnr-rr","ltr-rr","lcr-rr","nr-rr","clr-rr","or-rr","xr-rr",
  "lr-rr","cr-rr","ar-rr","sr-rr","mr-rr","dr-rr","alr-rr","slr-rr",
  -- 20
  "lpdr-ff","lndr-ff","ltdr-ff","lcdr-ff","hdr-ff","ldxr-ff","mxr-ff","mxdr-ff",
  "ldr-ff","cdr-ff","adr-ff","sdr-ff","mdr-ff","ddr-ff","awr-ff","swr-ff",
  "lper-ff","lner-ff","lter-ff","lcer-ff","her-ff","ledr-ff","axr-ff","sxr-ff",
  "ler-ff","cer-ff","aer-ff","ser-ff","mder-ff","der-ff","aur-ff","sur-ff",
  -- 40
  "sth-rx","la-rx","stc-rx","ic-rx","ex-rx","bal-rx","bct-rx",
  cc1("b%s-.x",8,"b-.x","nop-.x"),
  "lh-rx","ch-rx","ah-rx","sh-rx","mh-rx","bas-rx","cvd-rx","cvb-rx",
  "st-rx","lae-rx",nil,nil,"n-rx","cl-rx","o-rx","x-rx",
  "l-rx","c-rx","a-rx","s-rx","m-rx","d-rx","al-rx","sl-rx",
  -- 60
  "std-fx",nil,nil,nil,nil,nil,nil,"mxd-fx",
  "ld-fx","cd-fx","ad-fx","sd-fx","md-fx","dd-fx","aw-fx","sw-fx",
  "ste-fx","ms-rx",nil,nil,nil,nil,nil,nil,
  "le-fx","ce-fx","ae-fx","se-fx","mde-fx","de-fx","au-fx","su-fx",
  -- 80
  "ssm=s",nil,"lpsw=s","diag-rrs","jxh-rrJ","jxle-rrJ","bxh-rrs","bxle-rrs",
  "srl-r.s","sll-r.s","sra-r.s","sla-r.s","srdl-r.s","sldl-r.s","srda-r.s","slda-r.s",
  "stm-rrs","tm-us2","mvi-us2","ts=s","ni-us2","cli-us2","oi-us2","xi-us2",
  "lm-rrs","trace-rrs","lam-aas","stam-aas",
  [0xa5]={
    off=12, nbits=4,
    [0]="iihh-r.k","iihl-r.k","iilh-r.k","iill-r.k",
    "nihh-r.k","nihl-r.k","nilh-r.k","nill-r.k",
    "oihh-r.k","oihl-r.k","oilh-r.k","oill-r.k",
    "llihh-r.k","llihl-r.k","llilh-r.k","llill-r.k",
  },
  [0xa7]={
    off=12, nbits=4,
    [0]="tmlh-r.k","tmll-r.k","tmhh-r.k","tmhl-r.k",
    cc1("j%s=J",8),"bras-r.J","brct-r.J","brctg-r.J",
    "lhi-r.K","lghi-r.K","ahi-r.K","aghi-r.K",
    "mhi-r.K","mghi-r.K","chi-r.K","cghi-r.K",
  },
  [0xa8]="mvcle-rrs","clcle-rrs",nil,nil,"stnsm-us2","stosm-us2","sigp-rrs","mc-us2",
  [0xb1] = "lra-rx",
  [0xb2]={
    off=8, nbits=8,
    [0]="lbear=s","stbear=s","stidp=s",nil,"sck=s","stck=s","sckc=s","stckc=s",
    "spt=s","stpt=s","spka=s","ipk",nil,"ptlb",nil,nil,
    "spx=s","stpx=s","stap=s",nil,"sie=s",nil,nil,nil,
    "pc=s","sac=s","cfc=s",nil,nil,nil,nil,nil,
    -- b220
    nil,"ipte=rmrr34","ipm=-r","ivsk=-rr","iac=-r","ssar=-r","epar=-r","esar=-r",
    "pt=-rr","iske=-rr","rrbe=-rr","sske=m.rr23","tb=-rr","dxr=-ff","pgin=-rr","pgout=-rr",
    "csch","hsch","msch=s","ssch=s","stsch=s","tsch=s","tpi=s","sal",
    "rsch","stcrw=s","stcps=s","rchp","schm",nil,nil,nil,
    -- b240
    "bakr=-rr","cksm=-rr",nil,nil,"sqdr=-ff","sqer=-ff","stura=-rr","msta=-r",
    "palb","ereg=-rr","esta=-rr","lura=-rr","tar=-ar","cpya=-aa","sar=-ar","ear=-ra",
    "csp=-rr",nil,"msr=-rr",nil,"mvpg=-rr","mvst=-rr",nil,"cuse=-rr",
    "bsg=-rr",nil,"bsa=-rr",nil,nil,"clst=-rr","srst=-rr",
    [0x63]="cmpsc=-rr",
    [0x74]="siga=s",[0x76]="xsch",[0x77]="rp=s",
    [0x78]="stcke=s",[0x79]="sacf=s",[0x7c]="stckf=s",[0x7d]="stsi=s",
    [0x80]="lpp=s",[0x84]="lcctl=s",[0x85]="lpctl=s",[0x86]="qsi=s",[0x87]="lsctl=s",
    [0x8e]="qctri=s",[0x8f]="qpaci=s",
    [0x99]="srnm=s",[0x9c]="stfpc=s",[0x9d]="lfpc=s",
    [0xa5]="tre=-rr",[0xa6]="cu21=m.rr23",[0xa7]="cu12=m.rr23",
    [0xb0]="stfle=s",[0xb1]="stfl=s",[0xb2]="lpswe=s",
    [0xb8]="srnmb=s",[0xb9]="srnmt=s",[0xbd]="lfas=s",
    [0xe0]="scctr=-rr",[0xe1]="spctr=-rr",[0xe4]="ecctr=-rr",[0xe5]="epctr=-rr",
    [0xe8]="ppa=m.rr23",[0xec]="etnd=-r",[0xed]="ecpga=-rr",
    [0xf8]="tend",[0xfa]="niai=-mm",[0xfc]="tabort=s",[0xff]="trap4=s",
  },
  [0xb3]={
    off=8, nbits=8,
    -- b300
    [0]="lpebr=-ff","lnebr=-ff","ltebr=-ff","lcebr=-ff",
    "ldebr=-ff","lxdbr=-ff","lxebr=-ff","mxdbr=-ff",
    "kebr=-ff","cebr=-ff","aebr=-ff","sebr=-ff",
    "mdebr=-ff","debr=-ff","maebr=f.ff","msebr=f.ff",
    "lpdbr=-ff","lndbr=-ff","ltdbr=-ff","lcdbr=-ff",
    "sqebr=-ff","sqdbr=-ff","sqxbr=-ff","meebr=-ff",
    "kdbr=-ff","cdbr=-ff","adbr=-ff","sdbr=-ff",
    "mdbr=-ff","ddbr=-ff","madbr=f.ff","msdbr=f.ff",
    --b320
    nil,nil,nil,nil,"lder=-ff","lxdr=-ff","lxer=-ff",nil,
    nil,nil,nil,nil,nil,nil,"maer=f.ff","mser=f.ff",
    nil,nil,nil,nil,nil,nil,"sqxr=-ff","meer=-ff",
    "maylr=f.ff","mylr=f.ff","mayr=f.ff","myr=f.ff",
    "mayhr=f.ff","myhr=f.ff","madr=f.ff","msdr=f.ff",
    --b340
    "lpxbr=-ff","lnxbr=-ff","ltxbr=-ff","lcxbr=-ff",
    "ledbra=mmff314","ldxbra=mmff314","lexbra=mmff314","fixbra=mmff314",
    "kxbr=-ff","cxbr=-ff","axbr=-ff","sxbr=-ff",
    "mxbr=-ff","dxbr=-ff",nil,nil,
    "tbedr=m.ff2","tbdr=m.ff2",nil,"diebr=fmff314",
    nil,nil,nil,"fiebra=mmff314",
    "thder=-ff","thdr=-ff",nil,"didbr=fmff314",
    nil,nil,nil,"fidbra=mmff314",
    --b360
    "lpxr=-ff","lnxr=-ff","ltxr=-ff","lcxr=-ff",
    nil,"lxr=-ff","lexr=-ff","fixr=-ff",
    nil,"cxr=-ff",nil,nil,
    nil,nil,nil,nil,
    "lpdfr=-ff","lndfr=-ff","cpsdr=f.ff2","lcdfr=-ff",
    "lzer=-f","lzdr=-f","lzxr=-f","fier=-ff",
    nil,nil,nil,nil,
    nil,nil,nil,"fidr=-ff",
    --b380
    nil,nil,nil,nil,"sfpc=-rr","sfasr=-r",nil,nil,
    nil,nil,nil,nil,"efpc=-rr",nil,nil,nil,
    "celfbr=mmfr314","cdlfbr=mmfr314","cxlfbr=mmfr314",nil,
    "cefbra=mmfr314","cdfbra=mmfr314","cxfbra=mmfr314",nil,
    "cfebra=mmrf314","cfdbra=mmrf314","cfxbra=mmrf314",nil,
    "clfebr=mmrf314","clfdbr=mmrf314","clfxbr=mmrf314",nil,
    --b3a0
    "celgbr=mmfr314","cdlgbr=mmfr314","cxlgbr=mmfr314",nil,
    "cegbra=mmfr314","cdgbra=mmfr314","cxgbra=mmfr314",nil,
    "cgebra=mmrf314","cgdbra=mmrf314","cgxbra=mmrf314",nil,
    "clgebr=mmrf314","clgdbr=mmrf314","clgxbr=mmrf314",nil,
    nil,nil,nil,nil,"cefr=-fr","cdfr=-fr","cxfr=-fr",nil,
    "cfer=m.rf2","cfdr=m.rf2","cfxr=m.rf2",nil,nil,nil,nil,nil,
    --b3c0
    nil,"ldgr=-fr",nil,nil,
    "cegr=-fr","cdgr=-fr","cxgr=-fr",nil,
    "cger=m.rf2","cgdr=m.rf2","cgxr=m.rf2",nil,
    nil,"lgdr=-rf",nil,nil,
    "mdtra=fmff34","ddtra=fmff34","adtra=fmff34","sdtra=fmff34",
    "ldetr=.mff23","ledtr=mmff314","ltdtr=-ff","fidtr=mmff314",
    "mxtra=fmff34","dxtra=fmff34","axtra=fmff34","sxtra=fmff34",
    "lxdtr=.mff23","ldxtr=mmff314","ltxtr=-ff","fixtr=mmff314",
    --b3e0
    "kdtr=-ff","cgdtra=mmrf314","cudtr=-rf","csdtr=.mrf23",
    "cdtr=-ff","eedtr=-rf",nil,"esdtr=-rf",
    "kxtr=-ff","cgxtra=mmrf314","cuxtr=-rf","csxtr=.mrf23",
    "cxtr=-ff","eextr=-rf",nil,"esxtr=-rf",
    nil,"cdgtra=mmfr314","cdutr=-fr","cdstr=-fr",
    "cedtr=-ff","qadtr=fmff314","iedtr=f.fr2","rrdtr=fmfr314",
    nil,"cxgtra=mmfr314","cxutr=-fr","cxstr=-fr",
    "cextr=-ff","qaxtr=fmff314","iextr=f.fr2",nil,
  },
  [0xb6]="stctl-ccs",
  [0xb7]="lctl-ccs",
  [0xb9]={
    off=8, nbits=8,
    [0]="lpgr=-rr","lngr=-rr","ltgr=-rr","lcgr=-rr",
    "lgr=-rr","lurag=-rr","lgbr=-rr","lghr=-rr",
    "agr=-rr","sgr=-rr","algr=-rr","slgr=-rr",
    "msgr=-rr","dsgr=-rr","eregg=-rr","lrvgr=-rr",
    "lpgfr=-rr","lngfr=-rr","ltgfr=-rr","lcgfr=-rr",
    "lgfr=-rr",nil,"llgfr=-rr","llgtr=-rr",
    "agfr=-rr","sgfr=-rr","algfr=-rr","slgfr=-rr",
    "msgfr=-rr","dsgfr=-rr","kmac=-rr","lrvr=-rr",
    --b920
    "cgr=-rr","clgr=-rr",nil,nil,nil,"sturg=-rr","lbr=-rr","lhr=-rr",
    "pckmo","kma=r.rr2","kmf=-rr","kmo=-rr","pcc","kmctr=r.rr2","km=-rr","kmc=-rr",
    "cgfr=-rr","clgfr=-rr",nil,nil,nil,nil,nil,nil,
    "sortl=-rr","dfltcc=r.rr23","kdsa=-rr","nnpa",
    "ppno=-rr",nil,"kimd=m.rr23","klmd=m.rr23",
    --b940
    nil,"cfdtr=mmrf314","clgdtr=mmrf314","clfdtr=mmrf314",
    nil,nil,"bctgr=-rr",nil,
    nil,"cfxtr=mmrf314","clgxtr=mmrf314","clfxtr=mmrf314",nil,nil,nil,nil,
    nil,"cdftr=mmfr314","cdlgtr=mmfr314","cdlftr=mmfr314",nil,nil,nil,nil,
    nil,"cxftr=mmfr314","cxlgtr=mmfr314","cxlftr=mmfr314",nil,nil,nil,nil,
    --b960
    cc2("cgrt%s=-rr",16,"cgrt=m.rr23"),
    cc2("clgrt%s=-rr",16,"clgrt=m.rr23"),nil,nil,
    "nngrk=r.rr23","ocgrk=r.rr23","nogrk=r.rr23","nxgrk=r.rr23",
    "clzg=-rr","ctzg=-rr",nil,nil,
    "bextg=r.rr23","bdepg=r.rr23",nil,nil,
    nil,nil,cc2("crt%s=-rr",16,"crt=m.rr23"),cc2("clrt%s=-rr",16,"clrt=m.rr23"),
    "nnrk=r.rr23","ocrk=r.rr23","nork=r.rr23","nxrk=r.rr23",
    nil,nil,nil,nil, nil,nil,nil,nil,
    --b980
    "ngr=-rr","ogr=-rr","xgr=-rr","flogr=-rr",
    "llgcr=-rr","llghr=-rr","mlgr=-rr","dlgr=-rr",
    "alcgr=-rr","slbgr=-rr","cspg=-rr","rdp=rmrr314",
    nil,"epsw=-rr","idte=rmrr314","crdte=rmrr314",
    "trtt=m.rr23","trto=m.rr23","trot=m.rr23","troo=m.rr23",
    "llcr=-rr","llhr=-rr","mlr=-rr","dlr=-rr",
    "alcr=-rr","slbr=-rr","epair=-r","esair=-r",
    nil,"esea=-r","pti=-rr","ssair=-r",
    --b9a0
    nil,"tpei=-rr","ptf=-r",nil,nil,nil,nil,nil,
    nil,nil,"lptea=rmrr314",nil,"irbm=-rr",nil,"rrbm=-rr","pfmf=-rr",
    "cu14=m.rr23","cu24=m.rr23","cu41=-rr","cu42=-rr",nil,nil,nil,nil,
    nil,nil,nil,nil,nil,"trtre=m.rr23","srstu=-rr","trte=m.rr23",
    --b9c0
    "selfhr=rmrr34",nil,nil,nil,nil,nil,nil,nil,
    "ahhhr=r.rr23","shhhr=r.rr23","alhhhr=r.rr23","slhhhr=r.rr23",
    nil,"chhr=-rr",nil,"clhhr=-rr",
    nil,nil,nil,nil,nil,nil,nil,nil,
    "ahhlr=r.rr23","shhlr=r.rr23","alhhlr=r.rr23","slhhlr=r.rr23",
    nil,"chlr=-rr",nil,"clhlr=-rr",
    --b9e0
    cc1("locfhr%s=-rr",16,"locfhr=m.rr23"),"popcnt=m.rr23",
    cc1("locgr%s=-rr",16,"locgr=m.rr23"),"selgr=rmrr34",
    "ngrk=r.rr23","ncgrk=r.rr23","ogrk=r.rr23","xgrk=r.rr23",
    "agrk=r.rr23","sgrk=r.rr23","algrk=r.rr23","slgrk=r.rr23",
    "mgrk=r.rr23","msgrkc=r.rr23",nil,nil,
    "selr=rmrr34",nil,cc1("locr%s=-rr",16,"locr=m.rr23"),nil,
    "nrk=r.rr23","ncrk=r.rr23","ork=r.rr23","xrk=r.rr23",
    "ark=r.rr23","srk=r.rr23","alrk=r.rr23","slrk=r.rr23",
    nil,"msrkc=r.rr23",nil,nil,
  },
  [0xba]="cs-rrs",[0xbb]="cds-rrs",[0xbd]="clm-rms",
  [0xbe]="stcm-rms",[0xbf]="icm-rms",
  [0xc0]={
    off=12, nbits=4,
    [0]="larl-r.P","lgfi-r.I",nil,nil,
    cc1("jg%s=P",8),"brasl-r.P","xihf-r.i","xilf-r.i",
    "iihf-r.i","iilf-r.i","nihf-r.i","nilf-r.i",
    "oihf-r.i","oilf-r.i","llihf-r.i","llilf-r.i",
  },
  [0xc2]={
    off=12, nbits=4,
    [0]="msgfi-r.I","msfi-r.I",nil,nil,"slgfi-r.i","slfi-r.i",nil,nil,
    "agfi-r.I","afi-r.I","algfi-r.i","alfi-r.i",
    "cgfi-r.I","cfi-r.I","clgfi-r.i","clfi-r.i",
  },
  [0xc4]={
    off=12, nbits=4,
    [0]=nil,nil,"llhrl-r.P",nil,
    "lghrl-r.P","lhrl-r.P","llghrl-r.P","sthrl-r.P",
    "lgrl-r.P",nil,nil,"stgrl-r.P",
    "lgfrl-r.P","lrl-r.P","llgfrl-r.P","strl-r.P",
  },
  [0xc5]="bprp-mjp",
  [0xc6]={
    off=12, nbits=4,
    [0]="exrl-r.P",nil,"pfdrl-m.P",nil,
    "cghrl-r.P","chrl-r.P","clghrl-r.P","clhrl-r.P",
    "cgrl-r.P",nil,"clgrl-r.P",nil,
    "cgfrl-r.P","crl-r.P","clgfrl-r.P","clrl-r.P",
  },
  [0xc7]="bpp-m.sJ13",
  [0xc8]={
    off=12, nbits=4,
    [0]="mvcos-r.ss23","ectg-r.ss23","csst-r.ss23",nil,
    "lpd-r.ss","lpdg-r.ss","cal-r.ss","calg-r.ss",
    nil,nil,nil,nil,nil,nil,nil,"calgf-r.ss",
  },
  [0xcc]={
    off=12, nbits=4,
    [0]=nil,nil,nil,nil,nil,nil,"jcth-r.P",nil,
    "aih-r.I",nil,"alsih-r.I","alsihn-r.I",
    nil,"cih-r.I",nil,"clih-r.i",
  },
  [0xd0]="trtr-ns",[0xd1]="mvn-ns",[0xd2]="mvc-ns",[0xd3]="mvz-ns",
  [0xd4]="nc-ns",[0xd5]="clc-ns",[0xd6]="oc-ns",[0xd7]="xc-ns",
  [0xd9]="mvck-rrBDs4135",[0xda]="mvcp-rrBDs4135",[0xdb]="mvcs-rrBDs4135",
  [0xdc]="tr-ns",[0xdd]="trt-ns",[0xde]="ed-ns",[0xdf]="edmk-ns",
  [0xe1]="pku-LsBD24",[0xe2]="unpku-ns",
  [0xe3]={
    off=40, nbits=8,
    [0]=nil,nil,"ltg-ry","lrag-ry","lg-ry",nil,"cvby-ry",nil,
    "ag-ry","sg-ry","alg-ry","slg-ry","msg-ry","dsg-ry","cvbg-ry","lrvg-ry",
    nil,nil,"lt-ry","lray-ry","lgf-ry","lgh-ry","llgf-ry","llgt-ry",
    "agf-ry","sgf-ry","algf-ry","slgf-ry","msgf-ry","dsgf-ry","lrv-ry","lrvh-ry",
    --e320
    "cg-ry","clg-ry",nil,nil,"stg-ry","ntstg-ry","cvdy-ry",nil,
    nil,nil,"lzrg-ry",nil,nil,nil,"cvdg-ry","strvg-ry",
    "cgf-ry","clgf-ry","ltgf-ry",nil,"cgh-ry",nil,"pfd-my",nil,
    "agh-ry","sgh-ry","llzrgf-ry","lzrf-ry","mgh-ry",nil,"strv-ry","strvh-ry",
    --e340
    nil,nil,nil,nil,nil,nil,"bctg-ry",cc1("bi%s-.y",8,"bi-.y","bic-my"),
    "llgfsg-ry","stgsc-ry",nil,nil,"lgg-ry","lgsc-ry",nil,nil,
    "sty-ry","msy-ry",nil,"msc-ry","ny-ry","cly-ry","oy-ry","xy-ry",
    "ly-ry","cy-ry","ay-ry","sy-ry","mfy-ry",nil,"aly-ry","sly-ry",
    --e360
    "lxab-ry","llxab-ry","lxah-ry","llxah-ry","lxaf-ry","llxaf-ry","lxag-ry","llxag-ry",
    "lxaq-ry","llxaq-ry",nil,nil,nil,nil,nil,nil,
    "sthy-ry","lay-ry","stcy-ry","icy-ry",nil,"laey-ry","lb-ry","lgb-ry",
    "lhy-ry","chy-ry","ahy-ry","shy-ry","mhy-ry",nil,nil,nil,
    --e380
    "ng-rx","og-rx","xg-rx","msgc-ry","mg-ry","lgat-ry","mlg-rx","dlg-rx",
    "alcg-rx","slbg-rx",nil,nil,nil,nil,"stpq-rx","lpq-rx",
    "llgc-rx","llgh-rx",nil,nil,"llc-ry","llh-ry","ml-rx","dl-rx",
    "alc-rx","slb-rx",nil,nil,"llgtat-ry","llgfat-ry",nil,"lat-ry",
    --e3a0
    nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,
    nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,
    --e3c0
    "lbh-ry",nil,"llch-ry","stch-ry","lhh-ry",nil,"llhh-ry","sthh-ry",
    "lfhat-ry",nil,"lfh-ry","stfh-ry",nil,"chf-ry",nil,"clhf-ry",
  },
  [0xe5]={
    off=8, nbits=8,
    [0x00]="lasp=ss",[0x01]="tprot=ss",[0x02]="strag=ss",[0x0a]="mvcrl=ss",
    [0x0e]="mvcsk=ss",[0x0f]="mvcdk=ss",[0x44]="mvhhi=sK",[0x48]="mvghi=sK",
    [0x4c]="mvhi=sK",[0x54]="chhsi=sK",[0x55]="clhhsi=sk",[0x58]="cghsi=sK",
    [0x59]="clghsi=sk",[0x5c]="chsi=sK",[0x5d]="clfhsi=sk",[0x60]="tbegin=sk",
    [0x61]="tbeginc=sk",
  },
  [0xe8]="mvcin-ns",[0xe9]="pka-LsBD24",[0xea]="unpka-ns",
  [0xeb]={
    off=40, nbits=8,
    [0x04]="lmg-rrt",[0x0a]="srag-rrt",[0x0b]="slag-rrt",
    [0x0c]="srlg-rrt",[0x0d]="sllg-rrt",[0x0f]="tracg-rrt",
    [0x14]="csy-rrt",[0x16]="pfcr-rrt",[0x1c]="rllg-rrt",[0x1d]="rll-rrt",
    [0x20]="clmh-rmt",[0x21]="clmy-rmt",[0x23]="clt-rmt",[0x24]="stmg-rrt",
    [0x25]="stctg-cct",[0x26]="stmh-rrt",[0x2b]="clgt-rmt",
    [0x2c]="stcmh-rmt",[0x2d]="stcmy-rmt",[0x2f]="lctlg-cct",
    [0x30]="csg-rrt",[0x31]="cdsy-rrt",[0x3e]="cdsg-rrt",
    [0x44]="bxhg-rrt",[0x45]="bxleg-rrt",[0x4c]="ecag-rrt",
    [0x51]="tmy-ut2",[0x52]="mviy-ut2",[0x54]="niy-ut2",[0x55]="cliy-ut2",
    [0x56]="oiy-ut2",[0x57]="xiy-ut2",
    [0x6a]="asi-Ut2",[0x6e]="alsi-Ut2",
    [0x71]="lpswey=t",[0x7a]="agsi-Ut2",[0x7e]="algsi-Ut2",
    [0x80]="icmh-rmt",[0x81]="icmy-rmt",[0x8e]="mvclu-rrt",[0x8f]="clclu-rrt",
    [0x90]="stmy-rrt",[0x96]="lmh-rrt",[0x98]="lmy-rrt",
    [0x9a]="lamy-aat",[0x9b]="stamy-aat",
    [0xc0]="tp-l.BD3",
    [0xdc]="srak-rrt",[0xdd]="slak-rrt",[0xde]="srlk-rrt",[0xdf]="sllk-rrt",
    [0xe0]=cc1("locfh%s-r.t",12,"locfh-rmt13"),
    [0xe1]=cc1("stocfh%s-r.t",12,"stocfh-rmt13"),
    [0xe2]=cc1("locg%s-r.t",12,"locg-rmt13"),
    [0xe3]=cc1("stocg%s-r.t",12,"stocg-rmt13"),
    [0xe4]="lang-rrt",[0xe6]="laog-rrt",
    [0xe7]="laxg-rrt",[0xe8]="laag-rrt",[0xea]="laalg-rrt",
    [0xf2]=cc1("loc%s-r.t",12,"loc-rmt13"),
    [0xf3]=cc1("stoc%s-r.t",12,"stoc-rmt13"),
    [0xf4]="lan-rrt",
    [0xf6]="lao-rrt",[0xf7]="lax-rrt",[0xf8]="laa-rrt",[0xfa]="laal-rrt",
  },
  [0xec]={
    off=40, nbits=8,
    [0x42]=cc1("lochi%s-r.K",12,"lochi-rmK13"),
    [0x44]="brxhg-rrJ",[0x45]="brxlg-rrJ",
    [0x46]=cc1("locghi%s-r.K",12,"locghi-rmK13"),
    [0x4e]=cc1("lochhi%s-r.K",12,"lochhi-rmK13"),
    [0x51]="risblg-rruuu",[0x54]="rnsbg-rruuu",[0x55]="risbg-rruuu",
    [0x56]="rosbg-rruuu",[0x57]="rxsbg-rruuu",[0x59]="risbgn-rruuu",
    [0x5d]="risbhg-rruuu",
    [0x64]=cc2("cgrj%s-rrJ",32,"cgrj-rrJm124"),
    [0x65]=cc2("clgrj%s-rrJ",32,"clgrj-rrJm124"),
    [0x70]=cc2("cgit%s-r.K",32,"cgit-r.Km"),
    [0x71]=cc2("clgit%s-r.k",32,"clgit-r.km"),
    [0x72]=cc2("cit%s-r.K",32,"cit-r.Km"),
    [0x73]=cc2("clfit%s-r.k",32,"clfit-r.km"),
    [0x76]=cc2("crj%s-rrJ",32,"crj-rrJm124"),
    [0x77]=cc2("clrj%s-rrJ",32,"clrj-rrJm124"),
    [0x7c]=cc2("cgij%s-r.JU13",12,"cgij-rmJU14"),
    [0x7d]=cc2("clgij%s-r.Ju13",12,"clgij-rmJu14"),
    [0x7e]=cc2("cij%s-r.JU13",12,"cij-rmJU14"),
    [0x7f]=cc2("clij%s-r.Ju13",12,"clij-rmJu14"),
    [0xd8]="ahik-rrK",[0xd9]="aghik-rrK",[0xda]="alhsik-rrK",
    [0xdb]="alghsik-rrK",
    [0xe4]=cc2("cgrb%s-rrs",32,"cgrb-rrsm124"),
    [0xe5]=cc2("clgrb%s-rrs",32,"clgrb-rrsm124"),
    [0xf6]=cc2("crb%s-rrs",32,"crb-rrsm124"),
    [0xf7]=cc2("clrb%s-rrs",32,"clrb-rrsm124"),
    [0xfc]=cc2("cgib%s-r.sU13",12,"cgib-rmsU14"),
    [0xfd]=cc2("clgib%s-r.su13",12,"clgib-rmsu14"),
    [0xfe]=cc2("cib%s-r.sU13",12,"cib-rmsU14"),
    [0xff]=cc2("clib%s-r.su13",12,"clib-rmsu14"),
  },
  [0xed] = {
    off=40, nbits=8,
    [0x04]="ldeb-fx",[0x05]="lxdb-fx",[0x06]="lxeb-fx",[0x07]="mxdb-fx",
    [0x08]="keb-fx",[0x09]="ceb-fx",[0x0a]="aeb-fx",[0x0b]="seb-fx",
    [0x0c]="mdeb-fx",[0x0d]="deb-fx",[0x0e]="maeb-fxf3",[0x0f]="mseb-fxf3",
    [0x10]="tceb-fx",[0x11]="tcdb-fx",[0x12]="tcxb-fx",
    [0x14]="sqeb-fx",[0x15]="sqdb-fx",[0x17]="meeb-fx",
    [0x18]="kdb-fx",[0x19]="cdb-fx",[0x1a]="adb-fx",[0x1b]="sdb-fx",
    [0x1c]="mdb-fx",[0x1d]="ddb-fx",[0x1e]="madb-fxf3",[0x1f]="msdb-fxf3",
    [0x24]="lde-fx",[0x25]="lxd-fx",[0x26]="lxe-fx",
    [0x2e]="mae-fxf3",[0x2f]="mse-fxf3",
    [0x34]="sqe-fx",[0x35]="sqd-fx",[0x37]="mee-fx",[0x38]="mayl-fxf3",
    [0x39]="myl-fxf3",[0x3a]="may-fxf3",[0x3b]="my-fxf3",
    [0x3c]="mayh-fxf3",[0x3d]="myh-fxf3",[0x3e]="mad-fxf3",[0x3f]="msd-fxf3",
    [0x40]="sldt-fxf3",[0x41]="srdt-fxf3",[0x48]="slxt-fxf3",[0x49]="srxt-fxf3",
    [0x50]="tdcet-fx",[0x51]="tdget-fx",[0x54]="tdcdt-fx",
    [0x55]="tdgdt-fx",[0x58]="tdcxt-fx",[0x59]="tdgxt-fx",
    [0x64]="ley-fy",[0x65]="ldy-fy",[0x66]="stey-fy",[0x67]="stdy-fy",
    [0xa8]="czdt-nfm2",[0xa9]="czxt-nfm2",[0xaa]="cdzt-nfm2",[0xab]="cxzt-nfm2",
    [0xac]="cpdt-nfm2",[0xad]="cpxt-nfm2",[0xae]="cdpt-nfm2",[0xaf]="cxpt-nfm2",
    [0xee]="plo-rrss13",[0xef]="lmd-rrss",[0xf0]="srp-lmBDs4135",
  },
  [0xf1]="mvo-llBDBD4136",[0xf2]="pack-llBDBD4136",[0xf3]="unpk-llBDBD4136",
  [0xf8]="zap-llBDBD4136",[0xf9]="cp-llBDBD4136",[0xfa]="ap-llBDBD4136",
  [0xfb]="sp-llBDBD4136",[0xfc]="mp-llBDBD4136",[0xfd]="dp-llBDBD4136",
}

------------------------------------------------------------------------------

-- Output a nicely formatted line with an opcode and operands.
local function putop(ctx, mnem, operands)
  local code, pos, len = ctx.code, ctx.pos, ctx.len
  local hmax = ctx.hexdump
  local hex = ""
  if hmax > 0 then
    for i=pos,pos+len-1 do
      hex = hex..format("%02X", byte(code, i, i))
    end
    if #hex > hmax then hex = sub(hex, 1, hmax)..". "
    else hex = hex..rep(" ", hmax-#hex+2) end
  end
  local text = operands
  local rel = ctx.rel
  if rel then
    local sym = ctx.symtab[rel]
    if sym then text = text.."\t->"..sym end
  end
  ctx.out(format("%012x  %s%-10.10s%s\n", ctx.addr+pos - 1, hex, mnem, text))
  ctx.pos = pos+len
end

-- Fallback for incomplete opcodes at the end.
local function incomplete(ctx)
  ctx.len = ctx.stop+1 - ctx.pos
  return putop(ctx, "(incomplete)")
end

-- Fallback for unknown opcodes.
local function unknown(ctx)
  return putop(ctx, "(unknown)")
end

-- Determine instruction length from first byte.
local function insn_len(b)
  if b < 0x40 then return 2
  elseif b < 0xc0 then return 4
  else return 6 end
end

-- Extract an instruction field as an int.
local function geti(ctx, off, nbits)
  local f = 0
  local code = ctx.code
  local p = ctx.pos + off/8
  local b = byte(code, p, p)
  off = off % 8
  if off+nbits <= 8 then
    return (b >> (8-off-nbits)) & ((1 << nbits) - 1)
  end
  f = b & ((1 << (8-off)) - 1)
  nbits = nbits - (8-off)
  while nbits >= 8 do
    p = p+1
    f = 256*f + byte(code, p, p)
    nbits = nbits - 8
  end
  if nbits ~= 0 then
    p = p+1
    b = byte(code, p, p)
    f = (f << nbits) | (b >> (8-nbits))
  end
  return f
end

-- Retrieve a 20-bit displacement.
local function get20disp(ctx, off)
  local dl = geti(ctx, off, 12)
  local dh = geti(ctx, off+12, 8)
  return dl | (dh << 12)
end

-- Find translation pattern for the current instruction.
local function find_insn(ctx, b)
  local insn = map_insn[b]
  local default = nil
  while type(insn) ~= "string" do
    if not insn then return default end
    default = insn.default
    insn = insn[geti(ctx, insn.off, insn.nbits)]
  end
  return insn
end

-- Format a signed integer as an operand.
local function fmt_signed_int(num, numbits)
  local max = 1 << (numbits - 1)
  if numbits == 32 then
    if num > -1000 and num < 10000 then return format("%d", num)
    else return format("0x%x", num) end
  elseif num >= max then
    num = max+max-num
    return format(num < 1000 and "-%d" or "-0x%x", num)
  end
  return format(num < 10000 and "%d" or "0x%x", num)
end

-- Format an address without index register.
local function fmt_addr(disp, b)
  local d = fmt_signed_int(disp, 20)
  if b ~= 0 then return format("%s(%%r%u)", d, b) end
  return d
end

-- Format an address with index register.
local function fmt_xaddr(disp, x, b)
  local d = fmt_signed_int(disp, 20)
  if x ~= 0 and b ~= 0 then return format("%s(%%r%u,%%r%u)", d, x, b)
  elseif x == 0 and b ~= 0 then return format("%s(%%r%u)", d, b)
  elseif x ~= 0 and b == 0 then return format("%s(%%r%u,)", d, x)
  end
  return d
end

-- Extract a field and format it as signed int.
local function fmt_signed_field(ctx, off, numbits)
  local num = geti(ctx, off, numbits)
  return fmt_signed_int(num, numbits)
end

-- Extract and format a PC-relative address.
local function fmt_pcrel(ctx, off, numbits)
  local n = geti(ctx, off, numbits)
  n = (n << (32 - numbits)) ~>> (32 - numbits)
  local addr = ctx.addr+ctx.pos-1 + 2*n
  ctx.rel = addr
  return format("0x%x", addr)
end

-- Disassemble a single operand.
local function disass_opnd(ctx, off, f)
  if f == "m" then return format("%u", geti(ctx, off, 4))
  elseif f == "u" then return format("%u", geti(ctx, off, 8))
  elseif f == "o" then return format("%u", geti(ctx, off, 12))
  elseif f == "k" then
    local num = geti(ctx, off, 16)
    return format(num < 10000 and "%u" or "0x%x", num)
  elseif f == "i" then
    local num = geti(ctx, off, 32)
    return format(num < 10000 and "%u" or "0x%x", num)
  elseif f == "U" then return fmt_signed_field(ctx, off, 8)
  elseif f == "K" then return fmt_signed_field(ctx, off, 16)
  elseif f == "I" then return fmt_signed_field(ctx, off, 32)
  elseif f == "l" then return format("%u", geti(ctx, off, 4)+1)
  elseif f == "L" then return format("%u", geti(ctx, off, 8)+1)
  elseif f == "a" then return format("%%a%u", geti(ctx, off, 4))
  elseif f == "r" then return format("%%r%u", geti(ctx, off, 4))
  elseif f == "f" then return format("%%f%u", geti(ctx, off, 4))
  elseif f == "x" then
    local x = geti(ctx, off, 4)
    local b = geti(ctx, off+4, 4)
    local d = geti(ctx, off+8, 12)
    return fmt_xaddr(d, x, b)
  elseif f == "s" then
    local b = geti(ctx, off, 4)
    local d = geti(ctx, off+4, 12)
    return fmt_addr(d, b)
  elseif f == "t" then
    local b = geti(ctx, off, 4)
    local d = get20disp(ctx, off+4)
    return fmt_addr(d, b)
  elseif f == "y" then
    local x = geti(ctx, off, 4)
    local b = geti(ctx, off+4, 4)
    local d = get20disp(ctx, off+8)
    return fmt_xaddr(d, x, b)
  elseif f == "n" then
    local l = geti(ctx, off, 8)
    local b = geti(ctx, off+8, 4)
    local d = geti(ctx, off+12, 12)
    return format("%s(%u,%%r%u)", fmt_signed_int(d, 20), l+1, b)
  elseif f == "j" then return fmt_pcrel(ctx, off, 12)
  elseif f == "J" then return fmt_pcrel(ctx, off, 16)
  elseif f == "p" then return fmt_pcrel(ctx, off, 24)
  elseif f == "P" then return fmt_pcrel(ctx, off, 32)
  end
  return format("%s@%d", f, off)
end

-- Disassemble a single instruction.
local function disass_ins(ctx)
  local code = ctx.code
  local pos = ctx.pos
  local b1 = byte(code, pos, pos)
  local len = insn_len(b1)
  ctx.len = len
  ctx.rel = nil

  if pos+len-1 > ctx.stop then return incomplete(ctx) end
  local insn = find_insn(ctx, b1)
  if not insn then return unknown(ctx) end

  for mnem, fields, arr in gmatch(insn, "(%w+)([^%d]*)(%d*)") do
    local ops = {}
    local off = 0
    local n = 1
    for f in gmatch(fields, "(.)") do
      local nbits = map_fmtsz[f]
      if nbits < 0 then off = off - nbits -- skip
      else
	ops[n] = { off, f }
	off = off + nbits
	n = n+1
      end
    end
    -- Reorder the operands, if necessary, then compose the operand string.
    if arr ~= "" then
      local new_ops = {}
      local used = {}
      for idx in gmatch(arr, "(.)") do
        local i = tonumber(idx)
        new_ops[#new_ops + 1] = ops[i]
        used[i] = true
      end
      for i = 1, #ops do
        if not used[i] then
          new_ops[#new_ops + 1] = ops[i]
        end
      end
      ops = new_ops
    end
    local operands = ""
    for i = 1, #ops do
      local op = ops[i]
      if i > 1 then operands = operands .. "," end
      operands = operands .. disass_opnd(ctx, op[1], op[2])
    end
    return putop(ctx, mnem, operands)
  end
end

------------------------------------------------------------------------------

-- Disassemble a block of code.
local function disass_block(ctx, ofs, len)
  if not ofs then ofs = 0 end
  local stop = len and ofs+len or #ctx.code
  ofs = ofs + 1
  ctx.pos = ofs
  ctx.stop = stop
  ctx.rel = nil
  while ctx.pos <= stop do disass_ins(ctx) end
end

-- Extended API: create a disassembler context. Then call ctx:disass(ofs, len).
local function create(code, addr, out)
  local ctx = {}
  ctx.code = code
  ctx.addr = addr or 0
  ctx.out = out or io.write
  ctx.symtab = {}
  ctx.disass = disass_block
  ctx.hexdump = 12
  return ctx
end

-- Simple API: disassemble code (a string) at address and output via out.
local function disass(code, addr, out)
  create(code, addr, out):disass()
end

-- Return register name for RID.
local function regname(r)
  return r<16 and "%r"..r or "%f"..(r-16)
end

-- Public module functions.
return {
  create = create,
  disass = disass,
  regname = regname,
}
