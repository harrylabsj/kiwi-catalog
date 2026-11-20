"""Pure route-template matching helpers used by both API stacks.

This module intentionally owns no route table or handler policy. Keeping the
matcher isolated makes the app facade easier to split without changing the
fallback/FastAPI behavior.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

logger = logging.getLogger(__name__)

# 审查 P1-4：路径参数名此前直接拼进命名分组 (?P<{name}>...)，模板写错（如
# {a-b}、重复参数名）会在 re.match 编译时抛 re.error。异常从 match_path /
# resolve_route / dispatch_request 一路逃逸到 ASGI 层（fallback 的 __call__
# 只有 finally、没有 except），结果是该进程内所有本应 404 的未知路径都变成
# 裸文本 500，而 FastAPI 栈返回信封 500——同一坏扩展在双栈产生两种 500 形状。
# fail-closed：非法模板视为不匹配（该路由 404），而不是让不相关请求 500。
_PARAM_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PARAM_SEGMENT = re.compile(r"(?<=/)\{[A-Za-z_][A-Za-z0-9_]*(?::str)?\}(?=/|$)")
_CONVERTER_PATTERN = {
    "str": r"[^/]+",
    "int": r"[0-9]+",
    "float": r"[0-9]+(?:\.[0-9]+)?",
    "uuid": r"[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}",
    "path": r".*",
}
_NATIVE_PARAM = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*(?::([A-Za-z_][A-Za-z0-9_]*))?\}")


def match_path(template: str, path: str) -> dict[str, str] | None:
    """Return path parameters when *path* matches a route template.

    A template whose parameter segments are not valid Python identifiers is
    reported as a non-match (with a warning) instead of raising re.error, so
    one malformed extension route can never turn unrelated 404s into 500s.
    """
    regex = compile_template(template)
    match = regex.fullmatch(path) if regex is not None else None
    return match.groupdict() if match else None


def route_shape(template: str) -> str:
    """Name-independent template used to detect duplicate routes."""
    return _PARAM_SEGMENT.sub("{}", template)


@lru_cache(maxsize=512)
def _path_segments(template: str) -> tuple[tuple[str, str], ...]:
    segments = []
    for segment in template.split("/"):
        param = _NATIVE_PARAM.fullmatch(segment)
        if param:
            converter = param[1] or "str"
            if converter in _CONVERTER_PATTERN and converter != "path":
                segments.append((converter, ""))
                continue
        elif not _NATIVE_PARAM.search(segment):
            segments.append(("literal", segment))
            continue
        # A slash-spanning, mixed or custom converter cannot be assumed to
        # constrain later segments. Reserve the whole remaining prefix.
        segments.append(("path", ""))
        break
    return tuple(segments)


def paths_overlap(left: str, right: str) -> bool:
    """Detect extensions whose URL spaces intersect.

    For mixed/custom converters, reserve conservatively under the literal
    prefix. A registration warning is preferable to an undetected shadow.
    """
    a, b = _path_segments(left), _path_segments(right)
    for (kind_a, text_a), (kind_b, text_b) in zip(a, b, strict=False):
        if "path" in (kind_a, kind_b):
            return True
        if kind_a == kind_b == "literal":
            if text_a != text_b:
                return False
        elif kind_a == "literal" or kind_b == "literal":
            converter, value = (kind_b, text_a) if kind_a == "literal" else (kind_a, text_b)
            if re.fullmatch(_CONVERTER_PATTERN[converter], value) is None:
                return False
    return len(a) == len(b)


@lru_cache(maxsize=512)
def compile_template(template: str) -> re.Pattern[str] | None:
    parts = template.split("/")
    regex_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            param_name = part[1:-1]
            if _PARAM_NAME_PATTERN.fullmatch(param_name) is None:
                logger.warning("ignoring route template with invalid parameter name: %r", template)
                return None
            regex_parts.append(f"(?P<{param_name}>[^/]+)")
        else:
            if "{" in part or "}" in part:
                logger.warning("ignoring route template with embedded or unmatched braces: %r", template)
                return None
            regex_parts.append(re.escape(part))
    try:
        return re.compile("/".join(regex_parts))
    except re.error:
        # 重复参数名等编译期错误同样是模板缺陷，不是请求缺陷（审查 P1-4）。
        logger.warning("ignoring uncompilable route template: %r", template)
        return None
