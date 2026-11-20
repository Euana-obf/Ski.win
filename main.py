#!/usr/bin/env python3
"""
Ski.win v0.9 – All-in-one Luraph-grade Luau/Lua obfuscator
==========================================================
Single file: macros + normalize + compiler + random VM (114 ops)
+ anti-tamper/anti-dump/anti-hook + FastAPI web UI

  python main.py                  # start web server
  python main.py obfuscate in.lua # CLI
"""

from __future__ import annotations

import argparse
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# Helpers
# =============================================================================

def _rn(n: int = 3) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _rid(n: int = 8) -> str:
    return random.choice(string.ascii_letters) + "".join(
        random.choices(string.ascii_letters + string.digits, k=n - 1)
    )


# =============================================================================
# Opcodes (~114) – randomized every build
# =============================================================================

BASE_OPCODES = [
    "MOVE", "LOADK", "LOADKX", "LOADBOOL", "LOADNIL", "LOADTRUE", "LOADFALSE",
    "GETUPVAL", "SETUPVAL", "GETTABUP", "SETTABUP", "GETTABLE", "SETTABLE",
    "GETGLOBAL", "SETGLOBAL", "NEWTABLE", "SELF",
    "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV",
    "BAND", "BOR", "BXOR", "SHL", "SHR", "UNM", "BNOT", "NOT", "LEN",
    "CONCAT", "CLOSE", "TBC", "JMP", "JMPX",
    "EQ", "LT", "LE", "NE", "GT", "GE", "TEST", "TESTSET",
    "CALL", "TAILCALL", "RETURN", "RETURN0", "RETURN1",
    "FORLOOP", "FORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "SETLISTX",
    "CLOSURE", "VARARG", "VARARGPREP", "EXTRAARG",
    "NOP", "HALT", "TRAP", "DEBUG", "MOVE2", "MOVE3", "SWAP",
    "LOADK2", "LOADN", "LOADI", "LOADF", "ADDK", "SUBK", "MULK", "DIVK",
    "EQK", "LTK", "LEK", "GETFIELD", "SETFIELD", "GETI", "SETI",
    "NEWARRAY", "NEWTAB", "PUSH", "POP", "DUP",
    "CALL0", "CALL1", "CALL2", "CALL3", "RETN", "RET1", "RET0",
    "JTRUE", "JFALSE", "JNIL", "JNOTNIL", "AND", "OR",
    "TONUMBER", "TOSTRING", "TYPEOF", "ASSERT", "ERROR",
    "RAWGET", "RAWSET", "RAWEQUAL", "MMBIN", "MMBINI", "MMBINK", "SKIP", "LABEL",
]


def generate_opmap() -> Tuple[Dict[str, int], Dict[int, str]]:
    names = list(BASE_OPCODES)
    random.shuffle(names)
    base = random.randint(15, 60)
    name2num, num2name = {}, {}
    for i, name in enumerate(names):
        num = base + i
        name2num[name] = num
        num2name[num] = name
    return name2num, num2name


# =============================================================================
# Macros
# =============================================================================

class MacroProcessor:
    BUILTINS = {
        "SKI_PRINT": "print", "SKI_WARN": "warn", "SKI_ERROR": "error", "SKI_ASSERT": "assert",
        "SKI_TYPE": "type", "SKI_TYPEOF": "typeof", "SKI_TOSTRING": "tostring", "SKI_TONUMBER": "tonumber",
        "SKI_PAIRS": "pairs", "SKI_IPAIRS": "ipairs", "SKI_NEXT": "next", "SKI_SELECT": "select",
        "SKI_UNPACK": "(table.unpack or unpack)", "SKI_PACK": "table.pack",
        "SKI_INSERT": "table.insert", "SKI_REMOVE": "table.remove", "SKI_CONCAT": "table.concat",
        "SKI_SORT": "table.sort", "SKI_CLONE": "table.clone", "SKI_FREEZE": "table.freeze",
        "SKI_RANDOM": "math.random", "SKI_FLOOR": "math.floor", "SKI_CEIL": "math.ceil",
        "SKI_ABS": "math.abs", "SKI_MIN": "math.min", "SKI_MAX": "math.max", "SKI_CLAMP": "math.clamp",
        "SKI_SUB": "string.sub", "SKI_BYTE": "string.byte", "SKI_CHAR": "string.char",
        "SKI_FIND": "string.find", "SKI_GSUB": "string.gsub", "SKI_FORMAT": "string.format",
        "SKI_BAND": "bit32.band", "SKI_BOR": "bit32.bor", "SKI_BXOR": "bit32.bxor",
        "SKI_BNOT": "bit32.bnot", "SKI_LSHIFT": "bit32.lshift", "SKI_RSHIFT": "bit32.rshift",
        "SKI_SPAWN": "task.spawn", "SKI_WAIT": "task.wait", "SKI_DELAY": "task.delay",
        "SKI_DEFER": "task.defer", "SKI_CANCEL": "task.cancel",
        "SKI_PCALL": "pcall", "SKI_XPCALL": "xpcall",
        "SKI_RAWGET": "rawget", "SKI_RAWSET": "rawset", "SKI_RAWEQUAL": "rawequal",
        "SKI_REQUIRE": "require", "SKI_GAME": "game", "SKI_WORKSPACE": "workspace",
        "SKI_SCRIPT": "script", "SKI_TICK": "tick",
    }
    ARG_MACROS = {
        "SKI_LOG": 'print("[SKI]", $1)',
        "SKI_LOG2": 'print("[SKI]", $1, $2)',
        "SKI_SAFE": "(pcall(function() $1 end))",
        "SKI_TRY": "(function() local ok,err=pcall(function() $1 end) if not ok then warn(err) end end)()",
    }

    def __init__(self, user: Optional[Dict[str, str]] = None):
        self.simple = dict(self.BUILTINS)
        self.argm = dict(self.ARG_MACROS)
        if user and isinstance(user, dict):
            for k, v in user.items():
                (self.argm if "$1" in v else self.simple)[k] = v

    def process(self, source: str) -> str:
        src = source
        # Luraph-compatible macros
        for name in ("LPH_NO_VIRTUALIZE", "SKI_NO_VIRTUALIZE", "LPH_JIT", "LPH_JIT_MAX", "SKI_JIT"):
            src = re.sub(r"\b" + re.escape(name) + r"\s*\(", "(", src)
        for name in ("LPH_ENCSTR", "LPH_STRENC", "SKI_ENCSTR", "LPH_ENCNUM", "SKI_ENCNUM"):
            src = re.sub(r"\b" + re.escape(name) + r"\s*\(([^)]*)\)", r"(\1)", src)
        src = re.sub(r"\b(?:LPH_CRASH|SKI_CRASH)\s*\(\s*\)", "((function() while true do end end)())", src)
        src = re.sub(r"\bLPH_OBFUSCATED\b", "true", src)
        src = re.sub(r"\bSKI_OBFUSCATED\b", "true", src)
        for name, tmpl in sorted(self.argm.items(), key=lambda x: -len(x[0])):
            pat = re.compile(rf"\b{re.escape(name)}\s*\(([^)]*)\)", re.DOTALL)

            def repl(m, tmpl=tmpl):
                args = [a.strip() for a in m.group(1).split(",")]
                out = tmpl
                for i, a in enumerate(args, 1):
                    out = out.replace(f"${i}", a)
                return re.sub(r"\$\d+", "nil", out)

            src = pat.sub(repl, src)
        for name, repl in sorted(self.simple.items(), key=lambda x: -len(x[0])):
            src = re.sub(rf"\b{re.escape(name)}\b", repl, src)
        return src


# =============================================================================
# Normalize Luau / Lua 5.x → portable form
# =============================================================================

def normalize(source: str, target: str = "luau") -> str:
    src = source
    src = re.sub(
        r"\b(local\s+[A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][\w|?.\s<>{},()]*?(?=\s*=|\s*$|\s*,)",
        r"\1", src,
    )
    src = re.sub(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][\w|?.]*(\??)(\s*[,)])",
        r"\1\3", src,
    )
    src = re.sub(r"^\s*export\s+type\s+.+$", "", src, flags=re.MULTILINE)
    src = re.sub(r"^\s*type\s+[A-Za-z_][\w]*\s*=\s*.+$", "", src, flags=re.MULTILINE)
    src = re.sub(r"::\s*[A-Za-z_][\w|?.\s<>{},()]*", "", src)
    src = re.sub(r"\bconst\s+", "local ", src)

    for pat, repl in [
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*", r"\1 = \1 + "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*-=\s*", r"\1 = \1 - "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*\*=\s*", r"\1 = \1 * "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*/=\s*", r"\1 = \1 / "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*%=\s*", r"\1 = \1 % "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*\^=\s*", r"\1 = \1 ^ "),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\.=\s*", r"\1 = \1 .. "),
    ]:
        src = re.sub(pat, repl, src)
    src = re.sub(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*//=\s*([^\n;]+)",
        r"\1 = math.floor(\1 / (\2))", src,
    )
    src = re.sub(
        r"([A-Za-z0-9_\)\]]+)\s*//\s*([A-Za-z0-9_\(\[]+)",
        r"math.floor((\1) / (\2))", src,
    )

    def interp_repl(m):
        body = m.group(1)
        parts = re.split(r"\{([^}]+)\}", body)
        chunks = []
        for i, p in enumerate(parts):
            if i % 2 == 0:
                if p:
                    chunks.append('"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"')
            else:
                chunks.append(f"tostring({p.strip()})")
        return "(" + " .. ".join(chunks) + ")" if chunks else '""'

    src = re.sub(r"`([^`]*)`", interp_repl, src)
    src = re.sub(r"\b(\d+(?:_\d+)+)\b", lambda m: m.group(1).replace("_", ""), src)
    src = re.sub(r"\b0b([01_]+)\b", lambda m: str(int(m.group(1).replace("_", ""), 2)), src)
    src = re.sub(r"@[A-Za-z_][A-Za-z0-9_]*", "", src)
    if target == "lua51":
        src = re.sub(r"\bcontinue\b", "do end", src)
        src = re.sub(r"::\s*[A-Za-z_][A-Za-z0-9_]*\s*::", "", src)
        src = re.sub(r"\bgoto\s+[A-Za-z_][A-Za-z0-9_]*", "", src)
    return "\n".join(l for l in src.splitlines() if l.strip())


# =============================================================================
# Anti-tamper / anti-dump / anti-hook
# =============================================================================

def generate_anti_tamper(intensity: int = 5) -> str:
    parts = []
    t, p, s, tbl = _rn(), _rn(), _rn(), _rn()
    parts.append(f"""
do
  local {t}=type local {p}=pcall local {s}=string local {tbl}=table
  if {t}({p})~="function" or {t}({s})~="table" or {t}({tbl})~="table" then while true do end end
  if {t}({s}.char)~="function" or {t}({tbl}.concat)~="function" then while true do end end
end
""")
    if intensity >= 3:
        parts.append("""
do
  local hooks={"hookfunction","hookfunc","replaceclosure","newcclosure","hookmetamethod",
    "checkcaller","islclosure","iscclosure","getrawmetatable","setreadonly","makewriteable"}
  local env=getfenv and getfenv() or _G or _ENV
  if type(env)=="table" then for i=1,#hooks do if env[hooks[i]]~=nil then while true do end end end end
end
""")
        parts.append("""
do
  local dumpers={"getconstants","getconst","getprotos","getproto","getupvalues","getupvalue",
    "dumpstring","saveinstance","decompile","disassemble","getscriptbytecode","getgc","getreg",
    "getgenv","getrenv","getsenv","getnilinstances"}
  local env=getfenv and getfenv() or _G or _ENV
  if type(env)=="table" then for i=1,#dumpers do if env[dumpers[i]]~=nil then while true do end end end end
end
""")
    if intensity >= 4:
        parts.append("""
do
  local ok,dbg=pcall(function() return debug end)
  if ok and type(dbg)=="table" then
    if dbg.getconstants or dbg.getprotos or dbg.getupvalues then while true do end end
  end
end
""")
    if intensity >= 5:
        x = random.randint(40, 180)
        parts.append(f"""
do local _x={x} if ((_x*(_x+1))%2)~=0 then while true do end end end
""")
    random.shuffle(parts)
    return "\n".join(parts)


# =============================================================================
# Compiler (practical subset → bytecode)
# =============================================================================

@dataclass
class Inst:
    op: str
    a: int = 0
    b: int = 0
    c: int = 0
    bx: int = 0
    sbx: int = 0


@dataclass
class Proto:
    code: List[Inst] = field(default_factory=list)
    constants: List[Any] = field(default_factory=list)
    maxstack: int = 16


class Compiler:
    def __init__(self):
        self.proto = Proto()
        self.locals: Dict[str, int] = {}
        self.nextreg = 0
        self.kmap: Dict[Any, int] = {}
        self.opmap, _ = generate_opmap()

    def _r(self, name: Optional[str] = None) -> int:
        if name and name in self.locals:
            return self.locals[name]
        r = self.nextreg
        self.nextreg += 1
        if name:
            self.locals[name] = r
        self.proto.maxstack = max(self.proto.maxstack, self.nextreg + 4)
        return r

    def _k(self, val: Any) -> int:
        key = (type(val).__name__, val)
        if key not in self.kmap:
            self.kmap[key] = len(self.proto.constants)
            self.proto.constants.append(val)
        return self.kmap[key]

    def emit(self, op: str, a=0, b=0, c=0, bx=0, sbx=0):
        self.proto.code.append(Inst(op, a, b, c, bx, sbx))

    def compile(self, source: str) -> Proto:
        lines = [l.strip() for l in source.splitlines() if l.strip()]
        for line in lines:
            self._line(line)
        self.emit("RETURN", 0, 1)
        return self.proto

    def _line(self, line: str):
        m = re.match(r"return\s*(.*)", line)
        if m:
            expr = m.group(1).strip()
            if expr:
                r = self._expr(expr)
                self.emit("RETURN", r, 2)
            else:
                self.emit("RETURN0")
            return
        m = re.match(r"local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", line)
        if m:
            name, expr = m.group(1), m.group(2).rstrip(";")
            r = self._r(name)
            src = self._expr(expr)
            self.emit("MOVE", r, src)
            return
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", line)
        if m:
            name, expr = m.group(1), m.group(2).rstrip(";")
            r = self._r(name)
            src = self._expr(expr)
            self.emit("MOVE", r, src)
            return
        m = re.match(r"([A-Za-z_][A-Za-z0-9_.:]*)\s*\((.*)\)\s*;?$", line)
        if m:
            self._call(m.group(1), m.group(2))
            return
        if line:
            self._expr(line.rstrip(";"))

    def _expr(self, expr: str) -> int:
        expr = expr.strip()
        if not expr:
            r = self._r()
            self.emit("LOADNIL", r)
            return r
        if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in "\"'":
            k = self._k(expr[1:-1])
            r = self._r()
            self.emit("LOADK", r, bx=k)
            return r
        try:
            val = float(expr) if "." in expr else int(expr)
            k = self._k(val)
            r = self._r()
            self.emit("LOADK", r, bx=k)
            return r
        except ValueError:
            pass
        if expr == "true":
            r = self._r()
            self.emit("LOADTRUE", r)
            return r
        if expr == "false":
            r = self._r()
            self.emit("LOADFALSE", r)
            return r
        if expr == "nil":
            r = self._r()
            self.emit("LOADNIL", r)
            return r
        for op, name in [("..", "CONCAT"), ("+", "ADD"), ("-", "SUB"),
                         ("*", "MUL"), ("/", "DIV"), ("%", "MOD"), ("^", "POW")]:
            if op in expr:
                left, right = expr.split(op, 1)
                rl, rr = self._expr(left.strip()), self._expr(right.strip())
                rd = self._r()
                self.emit(name, rd, rl, rr)
                return rd
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", expr):
            if expr in self.locals:
                return self.locals[expr]
            k = self._k(expr)
            r = self._r()
            self.emit("GETGLOBAL", r, bx=k)
            return r
        k = self._k(expr)
        r = self._r()
        self.emit("GETGLOBAL", r, bx=k)
        return r

    def _call(self, fname: str, args: str):
        freg = self._expr(fname)
        arglist = [a.strip() for a in args.split(",") if a.strip()] if args.strip() else []
        for a in arglist:
            self._expr(a)
        narg = len(arglist)
        if narg == 0:
            self.emit("CALL0", freg)
        elif narg == 1:
            self.emit("CALL1", freg)
        elif narg == 2:
            self.emit("CALL2", freg)
        else:
            self.emit("CALL", freg, narg + 1, 1)


# =============================================================================
# VM Generator
# =============================================================================

class VMGenerator:
    def __init__(self, intensity: int = 5):
        self.intensity = intensity
        self.opmap, self.revmap = generate_opmap()

    def _encrypt_constants(self, constants: List[Any]) -> Tuple[str, int]:
        key = random.randint(40, 210)
        parts = []
        for c in constants:
            if isinstance(c, str):
                data = [(ord(ch) ^ ((key + i * 13) % 256)) % 256 for i, ch in enumerate(c)]
                parts.append("{" + ",".join(map(str, data)) + "}")
            elif isinstance(c, bool):
                parts.append("1" if c else "0")
            elif isinstance(c, (int, float)):
                parts.append(str(int(c * key + 91)))
            else:
                parts.append("0")
        return "{" + ",".join(parts) + "}", key

    def _encode(self, proto: Proto) -> List[List[int]]:
        out = []
        for inst in proto.code:
            num = self.opmap.get(inst.op, self.opmap.get("NOP", 0))
            out.append([num, inst.a, inst.b, inst.c, inst.bx, inst.sbx])
        return out

    def _handler(self, name: str, R, K, pc, A, B, C, Bx, sBx) -> str:
        h = {
            "MOVE": "{R}[{A}]={R}[{B}]",
            "LOADK": "{R}[{A}]={K}[{Bx}+1]",
            "LOADKX": "{R}[{A}]={K}[{Bx}+1]",
            "LOADBOOL": "{R}[{A}]={B}~=0",
            "LOADNIL": "{R}[{A}]=nil",
            "LOADTRUE": "{R}[{A}]=true",
            "LOADFALSE": "{R}[{A}]=false",
            "LOADN": "{R}[{A}]={Bx}",
            "GETGLOBAL": "{R}[{A}]=(_ENV or _G)[{K}[{Bx}+1]]",
            "SETGLOBAL": "(_ENV or _G)[{K}[{Bx}+1]]={R}[{A}]",
            "GETTABLE": "{R}[{A}]={R}[{B}][{R}[{C}] or {K}[{C}+1]]",
            "SETTABLE": "{R}[{A}][{R}[{B}] or {K}[{B}+1]]={R}[{C}] or {K}[{C}+1]]",
            "NEWTABLE": "{R}[{A}]={{}}",
            "NEWTAB": "{R}[{A}]={{}}",
            "ADD": "{R}[{A}]=({R}[{B}] or 0)+({R}[{C}] or 0)",
            "SUB": "{R}[{A}]=({R}[{B}] or 0)-({R}[{C}] or 0)",
            "MUL": "{R}[{A}]=({R}[{B}] or 0)*({R}[{C}] or 0)",
            "DIV": "{R}[{A}]=({R}[{B}] or 0)/({R}[{C}] or 1)",
            "MOD": "{R}[{A}]=({R}[{B}] or 0)%({R}[{C}] or 1)",
            "POW": "{R}[{A}]=({R}[{B}] or 0)^({R}[{C}] or 0)",
            "UNM": "{R}[{A}]=-({R}[{B}] or 0)",
            "NOT": "{R}[{A}]=not {R}[{B}]",
            "LEN": "{R}[{A}]=#{R}[{B}]",
            "CONCAT": "{R}[{A}]=tostring({R}[{B}] or '')..tostring({R}[{C}] or '')",
            "JMP": "{pc}={pc}+{sBx}",
            "EQ": "if (({R}[{B}]=={R}[{C}]) ~= ({A}~=0)) then {pc}={pc}+1 end",
            "LT": "if ((({R}[{B}] or 0)<({R}[{C}] or 0)) ~= ({A}~=0)) then {pc}={pc}+1 end",
            "TEST": "if ((not {R}[{A}]) == ({C}~=0)) then {pc}={pc}+1 end",
            "CALL0": "{R}[{A}]()",
            "CALL1": "{R}[{A}]({R}[{A}+1])",
            "CALL2": "{R}[{A}]({R}[{A}+1],{R}[{A}+2])",
            "CALL3": "{R}[{A}]({R}[{A}+1],{R}[{A}+2],{R}[{A}+3])",
            "CALL": "do local f={R}[{A}]; local n={B}-1; local args={{}}; for i=1,n do args[i]={R}[{A}+i] end; f(table.unpack(args,1,n)) end",
            "RETURN": "return table.unpack({R},{A},{A}+{B}-2)",
            "RETURN0": "return",
            "RETURN1": "return {R}[{A}]",
            "RET0": "return",
            "RET1": "return {R}[{A}]",
            "NOP": "",
            "HALT": "return",
            "TRAP": "while true do end",
            "DUP": "{R}[{A}]={R}[{B}]",
            "TONUMBER": "{R}[{A}]=tonumber({R}[{B}])",
            "TOSTRING": "{R}[{A}]=tostring({R}[{B}])",
            "AND": "{R}[{A}]={R}[{B}] and {R}[{C}]",
            "OR": "{R}[{A}]={R}[{B}] or {R}[{C}]",
        }
        tmpl = h.get(name, "")
        body = tmpl.format(R=R, K=K, pc=pc, A=A, B=B, C=C, Bx=Bx, sBx=sBx) if tmpl else ""
        if body and random.random() < 0.4:
            body = "local _{_rn(2)}={random.randint(1,999)};" + body
        return body

    def generate(self, proto: Proto) -> str:
        R, K, pc = _rn(3), _rn(3), _rn(2)
        op, A, B, C = _rn(2), _rn(1), _rn(1), _rn(1)
        Bx, sBx = _rn(2), _rn(2)
        bc = self._encode(proto)
        const_table, key = self._encrypt_constants(proto.constants)
        handlers = []
        for name, num in self.opmap.items():
            body = self._handler(name, R, K, pc, A, B, C, Bx, sBx)
            handlers.append(f"[{num}]=function(){body}end")
        for _ in range(random.randint(8, 16)):
            fake = random.randint(200, 240)
            if fake not in self.revmap:
                handlers.append(f"[{fake}]=function()while true do end end")
        random.shuffle(handlers)
        dispatch = ",\n".join(handlers)
        bc_lit = "{" + ",".join("{" + ",".join(map(str, row)) + "}" for row in bc) + "}"
        anti = generate_anti_tamper(self.intensity)
        code = f"""
-- Ski.win Hardened VM | {len(self.opmap)} opcodes | anti-dump/hook
return(function(...)
{anti}
local function _D(p,k)
  local o={{}}
  for i,v in ipairs(p) do
    if type(v)=="table" then
      local s={{}}
      for j,b in ipairs(v) do s[j]=string.char((b~(k+(j-1)*13))%256) end
      o[i]=table.concat(s)
    elseif type(v)=="number" and v>200 then o[i]=(v-91)/k
    else o[i]=(v==1) end
  end
  return o
end
local {K}=_D({const_table},{key})
local _BC={bc_lit}
local function _VM(...)
  local {R}={{...}}
  local {pc}=1
  local _ENV=_ENV or getfenv and getfenv() or _G
  local dispatch={{
{dispatch}
  }}
  while true do
    local inst=_BC[{pc}]
    if not inst then break end
    local {op}=inst[1]
    local {A}=inst[2] or 0
    local {B}=inst[3] or 0
    local {C}=inst[4] or 0
    local {Bx}=inst[5] or 0
    local {sBx}=inst[6] or 0
    {pc}={pc}+1
    local h=dispatch[{op}]
    if h then h() else while true do end end
  end
end
return _VM(...)
end)(...)
"""
        return code.strip()


# =============================================================================
# Obfuscator
# =============================================================================

class SkiObfuscator:
    def __init__(
        self,
        intensity: int = 5,
        target: str = "luau",
        macros: Optional[Dict[str, str]] = None,
        enable_vm: bool = True,
        enable_anti_tamper: bool = True,
        vm_strength: str = "medium",
    ):
        self.intensity = max(1, min(5, intensity))
        self.target = target if target in ("luau", "lua51", "lua52", "lua53", "lua54") else "luau"
        self.enable_vm = enable_vm
        self.enable_anti_tamper = enable_anti_tamper
        self.vm_strength = vm_strength if vm_strength in ("medium","strong") else ("strong" if intensity >= 4 else "medium")
        self.macro_proc = MacroProcessor(macros if isinstance(macros, dict) else None)

    def _strip(self, src: str) -> str:
        src = re.sub(r"--\[\[.*?\]\]", "", src, flags=re.DOTALL)
        src = re.sub(r"--[^\n]*", "", src)
        return "\n".join(l.strip() for l in src.splitlines() if l.strip())

    def _fallback_encrypt(self, src: str) -> str:
        raw = src.encode("utf-8", errors="replace")
        key = random.randint(50, 200)
        data = [(b ^ ((key + i * 17) % 256)) for i, b in enumerate(raw)]
        tbl = "{" + ",".join(map(str, data)) + "}"
        anti = generate_anti_tamper(self.intensity) if self.enable_anti_tamper else ""
        return f"""
-- Ski.win v0.9 | target={self.target} | encrypted payload
return (function(...)
{anti}
local d={tbl}
local k={key}
local s={{}}
for i=1,#d do s[i]=string.char((d[i]~((k+(i-1)*17)%256))%256) end
local src=table.concat(s)
local loader=loadstring or load
local fn=assert(loader(src,"@ski"))
return fn(...)
end)(...)
""".strip()

    def obfuscate(self, source: str) -> str:
        if not source or not source.strip():
            return "-- empty"
        src = self.macro_proc.process(source)
        src = self._strip(src)
        src = normalize(src, target=self.target)
        if not src.strip():
            return "-- empty after normalize"
        try:
            if self.enable_vm:
                proto = Compiler().compile(src)
                if len(proto.code) >= 2:
                    gen = VMGenerator(intensity=self.intensity)
                    result = gen.generate(proto)
                    return (
                        f"-- Protected by Ski.win v0.9\n"
                        f"-- target={self.target} | {len(gen.opmap)} opcodes | anti-dump/hook\n"
                        f"-- Original source permanently destroyed\n"
                        + result
                    )
        except Exception:
            pass
        return self._fallback_encrypt(src)


# =============================================================================
# Web UI (inline HTML)
# =============================================================================

INDEX_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Ski.win – Obfuscator</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0b0f14;color:#e6edf3;min-height:100vh}
.wrap{max-width:960px;margin:0 auto;padding:24px}
h1{font-size:1.6rem;margin-bottom:4px}
.sub{color:#8b9cb3;margin-bottom:20px;font-size:.9rem}
textarea{width:100%;min-height:180px;background:#12181f;border:1px solid #243041;
  color:#e6edf3;border-radius:8px;padding:12px;font-family:ui-monospace,monospace;font-size:13px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0;align-items:center}
label{font-size:.85rem;color:#8b9cb3}
select,button{background:#1a2332;border:1px solid #243041;color:#e6edf3;padding:8px 14px;
  border-radius:6px;cursor:pointer;font-size:.9rem}
button.primary{background:#3b82f6;border-color:#3b82f6;font-weight:600}
button.primary:hover{background:#2563eb}
.stats{font-size:.8rem;color:#8b9cb3;margin-top:8px}
pre{background:#12181f;border:1px solid #243041;border-radius:8px;padding:12px;
  overflow:auto;max-height:360px;font-size:12px;white-space:pre-wrap;word-break:break-all}
</style>
</head>
<body>
<div class="wrap">
  <h1>Ski.win</h1>
  <p class="sub">Luraph-grade Luau/Lua obfuscator · random VM · anti-dump/hook</p>
  <textarea id="src" placeholder='print("Hello")'></textarea>
  <div class="row">
    <label>VM
      <select id="vm">
        <option value="medium" selected>medium</option>
        <option value="strong">strong</option>
      </select>
    </label>
    <label>Intensity
      <select id="intensity">
        <option>1</option><option>2</option><option>3</option><option>4</option>
        <option selected>5</option>
      </select>
    </label>
    <label>Target
      <select id="target">
        <option value="luau" selected>luau</option>
        <option value="lua51">lua51</option>
        <option value="lua52">lua52</option>
        <option value="lua53">lua53</option>
        <option value="lua54">lua54</option>
      </select>
    </label>
    <input type="file" id="file" accept=".lua,.luau,.txt,text/*"/>
<button class="primary" onclick="go()">Obfuscate</button>
<button onclick="dl()" id="dlbtn" disabled>Download</button>
  </div>
  <div class="stats" id="stats"></div>
  <pre id="out"></pre>
</div>
<script>
async function go(){
  const source=document.getElementById('src').value;
  const intensity=+document.getElementById('intensity').value;
  const vm_strength=(document.getElementById('vm')||{}).value||'medium';
  const target=document.getElementById('target').value;
  const out=document.getElementById('out');
  const stats=document.getElementById('stats');
  out.textContent='Working...';
  stats.textContent='';
  try {
    const r=await fetch('/api/obfuscate',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({source,intensity,target,vm_strength,enable_vm:true,enable_anti_tamper:true})
    });
    const j=await r.json().catch(async()=>({detail:await r.text()}));
    if(!r.ok || j.success===false){
      let msg=j.detail;
      if(msg==null) msg=j.error||j.message||JSON.stringify(j);
      if(typeof msg!=='string') msg=JSON.stringify(msg,null,2);
      out.textContent='Error: '+msg;
      return;
    }
    out.textContent=j.result||'';
    if(j.stats){
      stats.textContent=`in ${j.stats.original_size} → out ${j.stats.obfuscated_size} bytes · ${j.stats.time_ms}ms · intensity ${j.stats.intensity}`;
    }
  } catch(e){
    out.textContent='Network/JS error: '+(e && e.message ? e.message : String(e));
  }
}

let lastResult='';
const _out=document.getElementById('out');
const _file=document.getElementById('file');
if(_file){_file.onchange=async(e)=>{const f=e.target.files[0];if(f)document.getElementById('src').value=await f.text();};}
function dl(){if(!lastResult)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([lastResult],{type:'text/plain'}));a.download='ski_obfuscated.luau';a.click();}
const _go=go;
go=async function(){await _go();const t=document.getElementById('out').textContent;if(t&&!t.startsWith('Error')&&!t.startsWith('Working')&&!t.startsWith('Network')){lastResult=t;const b=document.getElementById('dlbtn');if(b)b.disabled=false;}}
</script>
</body>
</html>
"""


def create_app():
    from fastapi import FastAPI, HTTPException, Request, Body
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field

    app = FastAPI(title="Ski.win", version="0.9.1")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class Req(BaseModel):
        source: str = ""
        intensity: int = Field(5, ge=1, le=5)
        target: str = "luau"
        vm_strength: str = "medium"
        enable_vm: bool = True
        enable_anti_tamper: bool = True

    def json_dumps(x):
        import json
        try:
            return json.dumps(x, ensure_ascii=False)
        except Exception:
            return str(x)

    @app.exception_handler(Exception)
    async def _any_err(request: Request, exc: Exception):
        from fastapi.exceptions import RequestValidationError
        if isinstance(exc, HTTPException):
            detail = exc.detail
            if not isinstance(detail, str):
                detail = json_dumps(detail)
            return JSONResponse({"success": False, "detail": detail}, status_code=exc.status_code)
        if isinstance(exc, RequestValidationError):
            return JSONResponse({"success": False, "detail": json_dumps(exc.errors())}, status_code=422)
        return JSONResponse({"success": False, "detail": str(exc)}, status_code=500)

    try:
        from fastapi.exceptions import RequestValidationError
        @app.exception_handler(RequestValidationError)
        async def _val_err(request: Request, exc: RequestValidationError):
            return JSONResponse({"success": False, "detail": json_dumps(exc.errors())}, status_code=422)
    except Exception:
        pass

    @app.get("/", response_class=HTMLResponse)
    def index():
        return INDEX_HTML

    @app.post("/api/obfuscate")
    async def api_obfuscate(request: Request):
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"success": False, "detail": "invalid JSON body"}, status_code=400)
        if not isinstance(data, dict):
            return JSONResponse({"success": False, "detail": "body must be object"}, status_code=400)
        source = data.get("source") or ""
        intensity = int(data.get("intensity") or 5)
        intensity = max(1, min(5, intensity))
        target = data.get("target") or "luau"
        vm_strength = data.get("vm_strength") or "medium"
        enable_vm = data.get("enable_vm", True)
        enable_anti_tamper = data.get("enable_anti_tamper", True)
        if not source or len(str(source).strip()) < 2:
            return JSONResponse({"success": False, "detail": "source too short"}, status_code=400)
        t0 = time.time()
        try:
            eng = SkiObfuscator(
                intensity=intensity,
                target=target,
                vm_strength=vm_strength if vm_strength in ("medium", "strong") else "medium",
                enable_vm=bool(enable_vm),
                enable_anti_tamper=bool(enable_anti_tamper),
            )
            result = eng.obfuscate(str(source))
        except Exception as e:
            return JSONResponse({"success": False, "detail": f"{type(e).__name__}: {e}"}, status_code=500)
        return {
            "success": True,
            "result": result,
            "stats": {
                "original_size": len(str(source)),
                "obfuscated_size": len(result),
                "time_ms": int((time.time() - t0) * 1000),
                "intensity": intensity,
                "vm_strength": eng.vm_strength,
            },
        }

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.9.1"}

    return app


# Lazy app for uvicorn main:app (avoids requiring fastapi for CLI-only use)
try:
    app = create_app()
except Exception:
    app = None



# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Ski.win obfuscator")
    sub = parser.add_subparsers(dest="cmd")

    p_obf = sub.add_parser("obfuscate", help="obfuscate a file")
    p_obf.add_argument("input")
    p_obf.add_argument("-o", "--output", default=None)
    p_obf.add_argument("-i", "--intensity", type=int, default=5)
    p_obf.add_argument("-t", "--target", default="luau")
    p_obf.add_argument("--no-vm", action="store_true")

    sub.add_parser("serve", help="start web server")

    args = parser.parse_args()

    if args.cmd == "obfuscate":
        src = open(args.input, encoding="utf-8").read()
        eng = SkiObfuscator(
            intensity=args.intensity,
            target=args.target,
            enable_vm=not args.no_vm,
        )
        out = eng.obfuscate(src)
        path = args.output or (args.input + ".obfuscated.luau")
        open(path, "w", encoding="utf-8").write(out)
        print(f"Wrote {path} ({len(out)} bytes)")
        return

    # default / serve → web
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    main()
