"""Safe pickle inspection — walk the opcode stream, never execute it.

`pickletools.genops` decodes opcodes without running them. This module is the
only place in Argus that reads a pickle stream, and it must never gain a call
to `pickle.load`, `torch.load`, or `joblib.load`. A scanner that detonates the
thing it is scanning is strictly worse than no scanner, because it also lends
the payload the scanner's own privileges.

Purity note: everything here is a pure function of `bytes`. Opening the file is
the CLI's job (docs/18 §2.2) — this module never touches a path, so it is safe
to run inside the detection service on a manifest that arrived over HTTP.

Extracting `module.name` from a pickle is not quite a straight read:

  * `GLOBAL` and `INST` carry "module name" inline as their argument.
  * `STACK_GLOBAL` (protocol 4) takes both from the stack, so the two string
    pushes before it must be tracked — this is exactly how a payload hides from
    a scanner that only greps for the `GLOBAL` opcode.
  * Either operand can arrive through the memo rather than as a literal, so
    memo puts and gets are tracked too.

The shadow stack is deliberately approximate: it models string pushes, memo
traffic, and the constant pushes that would otherwise misalign it. Anything
else pushes a sentinel. That is sufficient because `STACK_GLOBAL` is always
preceded by its two operands, and being approximate keeps this loop total —
it cannot raise on a stream shaped in a way we did not anticipate.
"""

from __future__ import annotations

import io
import pickletools
import zipfile

from .types import GlobalRef, MemberRef

# Decompression caps. A weights archive is attacker-supplied, so a zip bomb is
# a realistic way to turn "scan this model" into "fill the scanner's disk".
MAX_MEMBER_BYTES = 64 * 1024 * 1024      # per pickle member we will walk
MAX_TOTAL_PICKLE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10_000

# Opcodes whose argument is a literal string pushed onto the stack.
_STRING_PUSH = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})

# Non-string pushes we model only to keep the stack aligned.
_OPAQUE_PUSH = frozenset({
    "NONE", "NEWTRUE", "NEWFALSE", "BININT", "BININT1", "BININT2", "INT", "LONG",
    "LONG1", "LONG4", "BINFLOAT", "FLOAT", "BINBYTES", "SHORT_BINBYTES",
    "BINBYTES8", "BYTEARRAY8", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET",
    "EMPTY_TUPLE", "NEXT_BUFFER", "PERSID", "BINPERSID",
})

_MEMO_PUT = frozenset({"BINPUT", "LONG_BINPUT", "PUT"})
_MEMO_GET = frozenset({"BINGET", "LONG_BINGET", "GET"})

_UNKNOWN = object()


def _as_str(v) -> str:
    return v if isinstance(v, str) else "?"


def walk_pickle(data: bytes, member: str = "") -> tuple[list[GlobalRef], dict[str, int], list[str]]:
    """Walk one pickle stream.

    Returns `(globals, opcode_counts, errors)`. Never raises: a malformed
    stream yields whatever was decoded before the break plus an error string.
    A truncated or deliberately corrupt pickle is itself a finding — silently
    returning "no globals" would read as "clean", which is the one answer this
    function must never give by accident.
    """
    found: list[GlobalRef] = []
    counts: dict[str, int] = {}
    errors: list[str] = []

    stack: list = []
    memo: dict = {}

    try:
        for op, arg, pos in pickletools.genops(data):
            code = op.name
            counts[code] = counts.get(code, 0) + 1

            if code == "GLOBAL" or code == "INST":
                # pickletools joins the two newline-delimited lines with a space.
                text = _as_str(arg)
                module, _, name = text.partition(" ")
                found.append(GlobalRef(module=module, name=name, opcode=code,
                                       offset=pos, member=member))
                if code == "GLOBAL":
                    stack.append(_UNKNOWN)

            elif code == "STACK_GLOBAL":
                name = stack.pop() if stack else _UNKNOWN
                module = stack.pop() if stack else _UNKNOWN
                if module is _UNKNOWN or name is _UNKNOWN:
                    # Operands were computed rather than pushed literally. That
                    # is itself suspicious, so it is recorded rather than
                    # dropped — the rules decide what it means.
                    errors.append(f"STACK_GLOBAL at {pos} with non-literal operands")
                found.append(GlobalRef(
                    module=_as_str(module), name=_as_str(name),
                    opcode=code, offset=pos, member=member,
                ))
                stack.append(_UNKNOWN)

            elif code in ("EXT1", "EXT2", "EXT4"):
                # copyreg extension registry: the callable is named by an integer
                # code resolved at load time, so there is no module/name to read.
                found.append(GlobalRef(module="<copyreg.ext>", name=str(arg),
                                       opcode="EXT", offset=pos, member=member))
                stack.append(_UNKNOWN)

            elif code in _STRING_PUSH:
                stack.append(arg if isinstance(arg, str) else _UNKNOWN)
            elif code in _OPAQUE_PUSH:
                stack.append(_UNKNOWN)
            elif code == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else _UNKNOWN
            elif code in _MEMO_PUT:
                memo[arg] = stack[-1] if stack else _UNKNOWN
            elif code in _MEMO_GET:
                stack.append(memo.get(arg, _UNKNOWN))
            elif code == "POP":
                if stack:
                    stack.pop()
            elif code == "DUP":
                stack.append(stack[-1] if stack else _UNKNOWN)
            # Every other opcode (REDUCE, BUILD, TUPLE, APPENDS, …) leaves the
            # shadow stack alone. See the module docstring: approximate is
            # deliberate, because total beats precise here.

    except Exception as e:  # noqa: BLE001 — genops raises a wide range on junk
        errors.append(f"{type(e).__name__}: {e}")

    return found, counts, errors


def _merge_counts(into: dict[str, int], other: dict[str, int]) -> None:
    for k, v in other.items():
        into[k] = into.get(k, 0) + v


def walk_zip_archive(
    data: bytes,
) -> tuple[list[GlobalRef], dict[str, int], list[MemberRef], list[str]]:
    """Walk a `.pt`-style zip archive: enumerate members, walk pickle members.

    Member names are preserved verbatim. Normalizing them here would erase the
    path-traversal evidence that ARG-ART-006 exists to find.
    """
    found: list[GlobalRef] = []
    counts: dict[str, int] = {}
    members: list[MemberRef] = []
    errors: list[str] = []
    budget = MAX_TOTAL_PICKLE_BYTES

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001
        return found, counts, members, [f"not a readable zip: {type(e).__name__}: {e}"]

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            errors.append(f"archive has {len(infos)} members; walking the first {MAX_MEMBERS}")
            infos = infos[:MAX_MEMBERS]

        for info in infos:
            is_pickle = info.filename.endswith((".pkl", ".pickle")) or \
                info.filename.rsplit("/", 1)[-1] in ("data.pkl", "constants.pkl")
            members.append(MemberRef(
                name=info.filename, raw_name=info.filename,
                size=info.file_size, compress_type=info.compress_type,
                is_pickle=is_pickle,
            ))
            if not is_pickle:
                continue
            if info.file_size > MAX_MEMBER_BYTES or info.file_size > budget:
                errors.append(f"member {info.filename!r} skipped: {info.file_size} bytes over cap")
                continue
            try:
                blob = zf.read(info)
            except Exception as e:  # noqa: BLE001
                errors.append(f"member {info.filename!r} unreadable: {type(e).__name__}: {e}")
                continue
            budget -= len(blob)
            g, c, errs = walk_pickle(blob, member=info.filename)
            found.extend(g)
            _merge_counts(counts, c)
            errors.extend(f"[{info.filename}] {e}" for e in errs)

    return found, counts, members, errors


# --------------------------------------------------------------------------
# format sniffing
# --------------------------------------------------------------------------

_PICKLE_PROTO_HEADER = b"\x80"
_ZIP_MAGIC = b"PK\x03\x04"
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_GGUF_MAGIC = b"GGUF"
_ONNX_HINT = b"onnx"


def sniff_format(data: bytes, filename: str = "") -> str:
    """Best-effort format identification from magic bytes, then extension.

    Magic first: the extension is attacker-controlled metadata, and a payload
    named `model.safetensors` that is actually a pickle is precisely the case
    worth catching.
    """
    head = data[:512]
    lower = filename.lower()

    if head.startswith(_ZIP_MAGIC):
        # torch>=1.6 checkpoints, and also plain zips of anything.
        return "torch_zip"
    if head.startswith(_HDF5_MAGIC):
        return "keras_h5"
    if head.startswith(_GGUF_MAGIC):
        return "gguf"
    if head.startswith(_PICKLE_PROTO_HEADER) and len(head) > 1 and head[1] <= 6:
        return "numpy_pickle" if lower.endswith(".npy") else "pickle"

    # safetensors: 8-byte little-endian header length, then JSON starting '{'.
    #
    # Checked BEFORE the protocol-0 pickle heuristic below, and the ordering is
    # load-bearing: a safetensors header of 93 bytes starts with the byte 0x5D,
    # which is also the pickle EMPTY_LIST opcode. Sniffing pickle first
    # misidentifies one safetensors file in every few hundred purely on the
    # length of its header — and then reports a parse failure on the format we
    # tell people to migrate to.
    if len(data) >= 9:
        n = int.from_bytes(data[:8], "little")
        if 0 < n <= len(data) - 8 and data[8:9] == b"{":
            return "safetensors"

    # Protocol 0/1 streams have no magic; they start with an opcode. `c` is
    # GLOBAL, `(` is MARK, `]` EMPTY_LIST, `}` EMPTY_DICT — the realistic heads.
    if head[:1] in (b"c", b"(", b"]", b"}"):
        return "pickle"

    if _ONNX_HINT in head or lower.endswith(".onnx"):
        return "onnx"

    for ext, fmt in (
        (".safetensors", "safetensors"), (".gguf", "gguf"), (".h5", "keras_h5"),
        (".pkl", "pickle"), (".pickle", "pickle"), (".joblib", "joblib"),
        (".pt", "torch_zip"), (".pth", "torch_zip"), (".ckpt", "torch_zip"),
        (".bin", "pickle"), (".npy", "numpy_pickle"),
    ):
        if lower.endswith(ext):
            return fmt
    return "unknown"
