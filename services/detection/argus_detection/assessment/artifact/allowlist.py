"""Which `module.name` references are dangerous, ordinary, or unrecognized.

This file decides the false-positive rate of the entire L0 layer, so it is data
with a version rather than conditions scattered through rules.

The naive rule — "a pickle containing REDUCE is malicious" — fires on every
model ever saved. A normal PyTorch checkpoint resolves
`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict` and
`numpy.core.multiarray._reconstruct` dozens of times before it has loaded a
single weight. Any detector that cannot tell those from `os.system` is noise,
and noise gets muted, and then the real alert is invisible.

Resolution order, and it matters:

    1. DENY   an explicit dangerous callable   → alert (high/critical)
    2. ALLOW  a known-good framework target    → silent
    3. otherwise                               → unrecognized (medium, inventory)

DENY is checked first so an allowed *prefix* cannot shelter a dangerous name:
`torch.*` is ordinary, but `torch.serialization.load` nested inside a
checkpoint is not, and prefix-allowlisting alone would wave it through.

`builtins` is never prefix-allowed. `builtins.list` is fine and
`builtins.eval` is game over, so that module is name-level only.

Changing anything here changes verdicts. ALLOWLIST_VERSION is stamped into
every finding for the same reason `scoring_version` is: a verdict nobody can
reproduce is a verdict nobody can argue with.
"""

from __future__ import annotations

# Bump on ANY change to the sets below. Findings carry it; the quality gate
# pins it. Semantics: major = resolution order changed, minor = entries added
# or removed.
ALLOWLIST_VERSION = "1.1.0"

# Severity band for a denied reference. Kept beside the entry rather than in the
# rule so that adding a callable does not mean editing rule logic.
EXEC = "exec"        # arbitrary code / process execution  → critical
NET = "net"          # outbound network                    → critical
FS = "fs"            # filesystem mutation                 → high
OBFUSCATE = "obf"    # decode/decompress helpers           → medium
GADGET = "gadget"    # indirect-call primitives            → high

# --------------------------------------------------------------------------
# DENY — dangerous callables, by module. "*" denies every name in the module.
# --------------------------------------------------------------------------
DENY: dict[str, dict[str, str]] = {
    # -- process / code execution -------------------------------------------
    "os": {
        "system": EXEC, "popen": EXEC, "popen2": EXEC, "popen3": EXEC, "popen4": EXEC,
        "execv": EXEC, "execve": EXEC, "execvp": EXEC, "execvpe": EXEC,
        "execl": EXEC, "execle": EXEC, "execlp": EXEC, "execlpe": EXEC,
        "spawnv": EXEC, "spawnve": EXEC, "spawnl": EXEC, "spawnle": EXEC,
        "spawnlp": EXEC, "spawnlpe": EXEC, "spawnvp": EXEC, "spawnvpe": EXEC,
        "posix_spawn": EXEC, "posix_spawnp": EXEC, "fork": EXEC, "forkpty": EXEC,
        # filesystem mutation
        "remove": FS, "unlink": FS, "rmdir": FS, "removedirs": FS, "rename": FS,
        "renames": FS, "replace": FS, "chmod": FS, "chown": FS, "lchown": FS,
        "symlink": FS, "link": FS, "mkdir": FS, "makedirs": FS, "truncate": FS,
        "putenv": FS, "unsetenv": FS,
    },
    # The C modules behind `os` — same primitives, different import path, and a
    # payload that uses them evades a name-only check against "os".
    "posix": {
        "system": EXEC, "popen": EXEC, "execv": EXEC, "execve": EXEC,
        "spawnv": EXEC, "spawnve": EXEC, "posix_spawn": EXEC, "fork": EXEC,
        "forkpty": EXEC, "remove": FS, "unlink": FS, "rename": FS, "chmod": FS,
        "symlink": FS, "link": FS, "mkdir": FS, "rmdir": FS,
    },
    "nt": {"system": EXEC, "popen": EXEC, "spawnv": EXEC, "remove": FS, "unlink": FS},
    "subprocess": {
        "Popen": EXEC, "call": EXEC, "check_call": EXEC, "check_output": EXEC,
        "run": EXEC, "getoutput": EXEC, "getstatusoutput": EXEC,
    },
    "commands": {"getoutput": EXEC, "getstatusoutput": EXEC},  # py2 payloads
    "pty": {"spawn": EXEC, "fork": EXEC, "openpty": EXEC},
    "platform": {"popen": EXEC, "_syscmd_ver": EXEC},
    "runpy": {"_run_code": EXEC, "_run_module_code": EXEC, "run_path": EXEC, "run_module": EXEC},
    "timeit": {"timeit": EXEC, "repeat": EXEC},
    "code": {"interact": EXEC, "InteractiveInterpreter": EXEC, "InteractiveConsole": EXEC},
    "codeop": {"compile_command": EXEC, "Compile": EXEC},
    "bdb": {"run": EXEC, "runeval": EXEC, "runcall": EXEC},
    "pdb": {"run": EXEC, "runeval": EXEC, "runcall": EXEC, "set_trace": EXEC},
    "multiprocessing": {"Process": EXEC, "Pool": EXEC},
    "asyncio": {"create_subprocess_shell": EXEC, "create_subprocess_exec": EXEC},
    "ctypes": {
        "CDLL": EXEC, "cdll": EXEC, "WinDLL": EXEC, "windll": EXEC, "OleDLL": EXEC,
        "PyDLL": EXEC, "pydll": EXEC, "LibraryLoader": EXEC, "CFUNCTYPE": EXEC,
        "memmove": EXEC, "memset": EXEC, "cast": EXEC,
    },
    "ctypes.util": {"find_library": EXEC},
    # `types.CodeType` + `types.FunctionType` is the classic pickle RCE: build a
    # code object from raw bytecode, wrap it in a function, call it.
    "types": {"FunctionType": EXEC, "CodeType": EXEC, "MethodType": EXEC, "LambdaType": EXEC},
    "webbrowser": {"open": EXEC, "open_new": EXEC, "open_new_tab": EXEC, "get": EXEC},
    "antigravity": {"*": EXEC},  # imports webbrowser and opens a URL on import

    # -- interpreter primitives ---------------------------------------------
    # Name-level only. builtins.list is ordinary; builtins.eval is game over.
    "builtins": {
        "eval": EXEC, "exec": EXEC, "compile": EXEC, "__import__": EXEC,
        "open": FS, "input": EXEC, "breakpoint": EXEC,
        "getattr": GADGET, "setattr": GADGET, "delattr": GADGET,
        "globals": GADGET, "locals": GADGET, "vars": GADGET,
    },
    "__builtin__": {  # py2 spelling, still emitted by old payloads
        "eval": EXEC, "exec": EXEC, "execfile": EXEC, "compile": EXEC,
        "__import__": EXEC, "open": FS, "file": FS, "input": EXEC,
        "getattr": GADGET, "setattr": GADGET, "apply": GADGET,
    },
    "importlib": {"import_module": EXEC, "__import__": EXEC, "reload": EXEC},
    "importlib.util": {"spec_from_file_location": EXEC, "module_from_spec": EXEC},
    "imp": {"load_source": EXEC, "load_module": EXEC, "load_compiled": EXEC},
    # Indirect-call gadgets: harmless alone, arbitrary-call when composed.
    "operator": {"methodcaller": GADGET, "attrgetter": GADGET, "call": GADGET},

    # -- nested deserialization ---------------------------------------------
    "pickle": {"loads": EXEC, "load": EXEC, "Unpickler": EXEC},
    "_pickle": {"loads": EXEC, "load": EXEC, "Unpickler": EXEC},
    "cPickle": {"loads": EXEC, "load": EXEC},
    "marshal": {"loads": EXEC, "load": EXEC},
    "shelve": {"open": EXEC},
    "dill": {"loads": EXEC, "load": EXEC},
    "cloudpickle": {"loads": EXEC, "load": EXEC},
    "joblib": {"load": EXEC},
    "torch": {"load": EXEC},
    "torch.serialization": {"load": EXEC, "_load": EXEC},
    "numpy": {"load": EXEC},          # allow_pickle=True is a full pickle load
    "numpy.lib.npyio": {"load": EXEC},
    "pandas": {"read_pickle": EXEC},
    "yaml": {"load": EXEC, "unsafe_load": EXEC, "full_load": EXEC},

    # -- network -------------------------------------------------------------
    "socket": {
        "socket": NET, "create_connection": NET, "socketpair": NET,
        "create_server": NET, "getaddrinfo": NET, "gethostbyname": NET,
    },
    "_socket": {"socket": NET, "getaddrinfo": NET, "gethostbyname": NET},
    "urllib.request": {
        "urlopen": NET, "urlretrieve": NET, "Request": NET,
        "build_opener": NET, "install_opener": NET,
    },
    "urllib": {"urlopen": NET, "urlretrieve": NET},
    "urllib2": {"urlopen": NET, "Request": NET},
    "requests": {
        "get": NET, "post": NET, "put": NET, "patch": NET, "delete": NET,
        "head": NET, "request": NET, "Session": NET,
    },
    "httpx": {"get": NET, "post": NET, "request": NET, "Client": NET, "AsyncClient": NET},
    "aiohttp": {"ClientSession": NET, "request": NET},
    "http.client": {"HTTPConnection": NET, "HTTPSConnection": NET},
    "httplib": {"HTTPConnection": NET, "HTTPSConnection": NET},
    "ftplib": {"FTP": NET, "FTP_TLS": NET},
    "smtplib": {"SMTP": NET, "SMTP_SSL": NET},
    "telnetlib": {"Telnet": NET},
    "paramiko": {"SSHClient": NET, "Transport": NET},
    "xmlrpc.client": {"ServerProxy": NET},
    "xmlrpclib": {"ServerProxy": NET},

    # -- filesystem mutation --------------------------------------------------
    "shutil": {
        "copy": FS, "copy2": FS, "copyfile": FS, "copytree": FS, "move": FS,
        "rmtree": FS, "make_archive": FS, "unpack_archive": FS, "chown": FS,
    },
    "io": {"open": FS, "FileIO": FS, "open_code": EXEC},
    "tempfile": {"NamedTemporaryFile": FS, "mkstemp": FS, "TemporaryFile": FS},
    "pathlib": {"PosixPath": FS, "WindowsPath": FS},  # only reachable as a call target

    # -- obfuscation helpers --------------------------------------------------
    # Medium, not critical: `_codecs.encode` legitimately appears when bytes are
    # pickled at protocol 0/1, so this band exists to note "something is being
    # decoded here" without claiming intent.
    "base64": {
        "b64decode": OBFUSCATE, "b64encode": OBFUSCATE, "b85decode": OBFUSCATE,
        "b32decode": OBFUSCATE, "b16decode": OBFUSCATE, "a85decode": OBFUSCATE,
        "decodebytes": OBFUSCATE, "urlsafe_b64decode": OBFUSCATE,
    },
    "zlib": {"decompress": OBFUSCATE, "decompressobj": OBFUSCATE},
    "bz2": {"decompress": OBFUSCATE, "BZ2Decompressor": OBFUSCATE},
    "lzma": {"decompress": OBFUSCATE, "LZMADecompressor": OBFUSCATE},
    "gzip": {"decompress": OBFUSCATE, "GzipFile": OBFUSCATE},
    "binascii": {"a2b_base64": OBFUSCATE, "unhexlify": OBFUSCATE},
}

# --------------------------------------------------------------------------
# ALLOW — the ordinary machinery of saved models.
#
# Derived from what real serializers actually emit. Every entry here is a
# deliberate decision that a payload could in principle abuse it and we accept
# that, because the alternative is a detector nobody leaves switched on.
# --------------------------------------------------------------------------

# Whole namespaces that are ordinary. DENY is still checked first, so a
# dangerous name inside one of these is not sheltered.
ALLOW_PREFIXES: tuple[str, ...] = (
    "torch.",
    "torchvision.",
    "torchaudio.",
    "numpy.",
    "scipy.",
    "sklearn.",
    "pandas.",
    "transformers.",
    "sentence_transformers.",
    "tokenizers.",
    "huggingface_hub.",
    "safetensors.",
    "PIL.",
    "matplotlib.",
    "networkx.",
    "xgboost.",
    "lightgbm.",
    "catboost.",
    "joblib.numpy_pickle",
)

# Bare module names that are ordinary in full (no dangerous surface at all).
ALLOW_MODULES: frozenset[str] = frozenset({
    "collections",
    "collections.abc",
    "copyreg",
    "copy_reg",          # py2 spelling
    "datetime",
    "decimal",
    "fractions",
    "uuid",
    "enum",
    "dataclasses",
    "zoneinfo",
    "argparse",
    "re",
    "string",
    "textwrap",
    "math",
    "cmath",
    "statistics",
    "array",
    "struct",
    "heapq",
    "bisect",
    "itertools",
    "abc",
    "typing",
    "torch",             # DENY carves out torch.load above
    "numpy",             # DENY carves out numpy.load above
    "sklearn",
    "scipy",
    "pandas",
    "transformers",
    "sentence_transformers",
    # A prefix entry ("tokenizers.") does not cover the bare module, and these
    # packages export their main class at top level — `tokenizers.Tokenizer`,
    # `xgboost.Booster`, `PIL.Image`. Without these the most ordinary model in
    # the corpus reports an unrecognized reference, which is how an inventory
    # signal turns into background noise people learn to skip.
    "tokenizers",
    "torchvision",
    "torchaudio",
    "safetensors",
    "huggingface_hub",
    "PIL",
    "networkx",
    "xgboost",
    "lightgbm",
    "catboost",
})

# Name-level allowances inside modules that are otherwise partly denied.
ALLOW_NAMES: dict[str, frozenset[str]] = {
    "builtins": frozenset({
        "list", "dict", "set", "frozenset", "tuple", "bytearray", "bytes",
        "str", "int", "float", "complex", "bool", "object", "type",
        "slice", "range", "reversed", "sorted", "len", "min", "max", "sum",
        "abs", "round", "divmod", "pow", "hash", "repr", "format",
        "NoneType", "Exception", "ValueError", "TypeError", "KeyError",
        "IndexError", "AttributeError", "RuntimeError", "StopIteration",
    }),
    "__builtin__": frozenset({
        "list", "dict", "set", "frozenset", "tuple", "bytearray", "str",
        "unicode", "int", "long", "float", "complex", "bool", "object",
    }),
    # functools.partial is a wrapper a payload can abuse, but it is also how
    # a great many legitimate objects are reconstructed. Denying it would
    # produce constant false alarms; the callable it wraps is judged on its
    # own merits by its own GlobalRef, which is the reference that matters.
    "functools": frozenset({"partial", "reduce", "cmp_to_key", "lru_cache"}),
    "operator": frozenset({
        "add", "sub", "mul", "truediv", "floordiv", "mod", "neg", "pos",
        "eq", "ne", "lt", "le", "gt", "ge", "itemgetter", "index",
    }),
    # Protocol 0/1 pickles route bytes through _codecs.encode(..., 'latin1').
    # Extremely common in legacy checkpoints; the payload risk lives in
    # base64/zlib decode chains, which DENY covers.
    "_codecs": frozenset({"encode", "decode"}),
    "codecs": frozenset({"encode", "decode"}),
    # Instantiating a path object is inert; calling a method on one is the
    # gadget, and operator.methodcaller is denied above.
    "pathlib": frozenset({"Path", "PurePath", "PurePosixPath"}),
}


def classify(module: str, name: str, first_party_prefixes: tuple[str, ...] = ()) -> tuple[str, str]:
    """Classify one global reference.

    Returns `(verdict, band)` where verdict is `denied` | `allowed` |
    `first_party` | `unrecognized`, and band is the DENY band (EXEC/NET/FS/
    OBFUSCATE/GADGET) or "" when not denied.

    Pure and total: any input produces a verdict, which is what lets the engine
    stay a pure function of the manifest.
    """
    # 1. DENY first — an allowed prefix must never shelter a dangerous name.
    entry = DENY.get(module)
    if entry is not None:
        band = entry.get("*") or entry.get(name)
        if band:
            return "denied", band

    # 2. ALLOW.
    if module in ALLOW_MODULES:
        return "allowed", ""
    named = ALLOW_NAMES.get(module)
    if named is not None and name in named:
        return "allowed", ""
    if module.startswith(ALLOW_PREFIXES):
        return "allowed", ""

    # 3. The customer's own code. Reported separately from "unrecognized" so an
    #    inventory of third-party references stays readable.
    if first_party_prefixes and module.startswith(tuple(first_party_prefixes)):
        return "first_party", ""

    return "unrecognized", ""
