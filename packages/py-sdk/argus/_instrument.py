"""Auto-instrumentation for the OpenAI and Anthropic Python SDKs.

Patches the resource `create` methods at the class level (async + sync), so every
client instance is covered — including OpenAI-compatible providers (DeepSeek,
Kimi, Qwen) that use AsyncOpenAI with a custom base_url. Non-streaming only;
streaming calls pass through untouched. Everything is defensive: if a SDK isn't
installed or its internals differ, instrumentation silently no-ops.
"""
from __future__ import annotations

from . import _config as cfg
from ._tracing import Trace, current_trace


def capture_generation(name, **gen):
    """Attach a captured generation to the active trace, or emit a standalone one."""
    if not cfg.is_enabled():
        return
    active = current_trace()
    if active is not None:
        active.generation(name, **gen)
        return
    t = Trace(name)
    t.generation(name, **gen)
    t.finish()


def _provider_from_client(client) -> str:
    try:
        host = str(getattr(client, "base_url", "") or "").lower()
    except Exception:
        host = ""
    for frag, prov in (
        ("openai.com", "openai"), ("anthropic.com", "anthropic"),
        ("deepseek", "deepseek"), ("moonshot", "kimi"), ("dashscope", "qwen"),
        ("googleapis", "google"), ("z.ai", "zhipu"), ("bigmodel", "zhipu"),
    ):
        if frag in host:
            return prov
    return ""


def _messages_to_text(messages, system=None) -> str:
    lines = []
    if system:
        lines.append("system: " + (system if isinstance(system, str) else str(system)))
    for m in messages or []:
        role = (m.get("role") if isinstance(m, dict) else getattr(m, "role", "user")) or "user"
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
        if isinstance(content, list):
            parts = []
            for p in content:
                if isinstance(p, dict):
                    parts.append(p.get("text") or ("[image]" if p.get("type", "").startswith("image") else ""))
                else:
                    parts.append(getattr(p, "text", "") or "")
            content = "\n".join(x for x in parts if x)
        lines.append(f"{role}: {content}")
    return "\n".join(lines)


# ------------------------- OpenAI -------------------------

def _record_openai(resource, kwargs, resp, provider):
    try:
        model = kwargs.get("model", "") or getattr(resp, "model", "")
        text_in = _messages_to_text(kwargs.get("messages"))
        choice = resp.choices[0]
        out = getattr(choice.message, "content", "") or ""
        usage = getattr(resp, "usage", None)
        in_tok = getattr(usage, "prompt_tokens", 0) if usage else 0
        out_tok = getattr(usage, "completion_tokens", 0) if usage else 0
        capture_generation(
            model or provider, model=model, provider=provider or "openai",
            input=text_in, output=out, input_tokens=in_tok, output_tokens=out_tok,
            finish_reason=getattr(choice, "finish_reason", "") or "",
        )
    except Exception as e:
        cfg.log("openai record failed", e)


def _install_openai():
    try:
        from openai.resources.chat import completions as comp
    except Exception:
        return
    for cls_name in ("AsyncCompletions", "Completions"):
        cls = getattr(comp, cls_name, None)
        if cls is None or getattr(cls, "_argus", False):
            continue
        orig = cls.create
        is_async = cls_name.startswith("Async")

        if is_async:
            async def create(self, *args, __orig=orig, **kwargs):
                if not cfg.is_enabled() or kwargs.get("stream"):
                    return await __orig(self, *args, **kwargs)
                resp = await __orig(self, *args, **kwargs)
                _record_openai(self, kwargs, resp, _provider_from_client(getattr(self, "_client", None)))
                return resp
        else:
            def create(self, *args, __orig=orig, **kwargs):
                if not cfg.is_enabled() or kwargs.get("stream"):
                    return __orig(self, *args, **kwargs)
                resp = __orig(self, *args, **kwargs)
                _record_openai(self, kwargs, resp, _provider_from_client(getattr(self, "_client", None)))
                return resp

        cls.create = create
        cls._argus = True


# ------------------------- Anthropic -------------------------

def _record_anthropic(kwargs, resp, provider):
    try:
        model = kwargs.get("model", "") or getattr(resp, "model", "")
        text_in = _messages_to_text(kwargs.get("messages"), kwargs.get("system"))
        blocks = getattr(resp, "content", []) or []
        out = "\n".join(getattr(b, "text", "") or "" for b in blocks).strip()
        usage = getattr(resp, "usage", None)
        in_tok = getattr(usage, "input_tokens", 0) if usage else 0
        out_tok = getattr(usage, "output_tokens", 0) if usage else 0
        capture_generation(
            model or provider, model=model, provider=provider or "anthropic",
            input=text_in, output=out, input_tokens=in_tok, output_tokens=out_tok,
            finish_reason=getattr(resp, "stop_reason", "") or "",
        )
    except Exception as e:
        cfg.log("anthropic record failed", e)


def _install_anthropic():
    try:
        from anthropic.resources import messages as msg
    except Exception:
        return
    for cls_name in ("AsyncMessages", "Messages"):
        cls = getattr(msg, cls_name, None)
        if cls is None or getattr(cls, "_argus", False):
            continue
        orig = cls.create
        is_async = cls_name.startswith("Async")

        if is_async:
            async def create(self, *args, __orig=orig, **kwargs):
                if not cfg.is_enabled() or kwargs.get("stream"):
                    return await __orig(self, *args, **kwargs)
                resp = await __orig(self, *args, **kwargs)
                _record_anthropic(kwargs, resp, _provider_from_client(getattr(self, "_client", None)))
                return resp
        else:
            def create(self, *args, __orig=orig, **kwargs):
                if not cfg.is_enabled() or kwargs.get("stream"):
                    return __orig(self, *args, **kwargs)
                resp = __orig(self, *args, **kwargs)
                _record_anthropic(kwargs, resp, _provider_from_client(getattr(self, "_client", None)))
                return resp

        cls.create = create
        cls._argus = True


def install(config: "cfg.Config"):
    if config.instrument_openai:
        try:
            _install_openai()
        except Exception as e:
            cfg.log("openai install failed", e)
    if config.instrument_anthropic:
        try:
            _install_anthropic()
        except Exception as e:
            cfg.log("anthropic install failed", e)
