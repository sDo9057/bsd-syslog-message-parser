"""Parser for RFC 3164 BSD syslog messages.

Distributed under the terms of the MIT License.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Optional, Tuple


__all__ = ["SyslogMessage", "parse", "ParseError"]


FACILITY_NAMES: Tuple[str, ...] = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
    "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
)

SEVERITY_NAMES: Tuple[str, ...] = (
    "emerg", "alert", "crit", "err", "warning", "notice", "info",
    "debug",
)


class ParseError(ValueError):
    """Raised when a datagram cannot be parsed as an RFC 3164 syslog message."""


@dataclass(frozen=True)
class SyslogMessage:
    """A parsed RFC 3164 syslog message.

    ``timestamp`` is timezone-aware (UTC) when RFC 3164 provides a year;
    it is ``None`` when the year had to be inferred, because inferring a
    year is a policy decision the caller should own.
    """

    priority: int
    facility: int
    severity: int
    facility_name: str
    severity_name: str
    timestamp: Optional[_dt.datetime]
    hostname: str
    tag: str
    message: str


def parse(datagram: str) -> SyslogMessage:
    """Parse a single RFC 3164 syslog datagram.

    Raises:
        ParseError: If the datagram does not begin with a valid ``<PRI>``
            token or the PRI value is out of range.
    """
    if not isinstance(datagram, str):
        raise ParseError("datagram must be a string")

    s = datagram
    if len(s) < 2 or s[0] != "<":
        raise ParseError("datagram must start with '<'")

    end = 1
    while end < len(s) and s[end].isdigit():
        end += 1
    if end == 1 or end >= len(s) or s[end] != ">":
        raise ParseError("missing '>' to close <PRI>")

    priority = int(s[1:end])
    if priority < 0 or priority > 191:
        raise ParseError("priority value out of range [0, 191]")

    facility = priority >> 3
    severity = priority & 0x07
    facility_name = FACILITY_NAMES[facility] if facility < len(FACILITY_NAMES) else "unknown"
    severity_name = SEVERITY_NAMES[severity]

    rest = s[end + 1:]
    ts, rest = _parse_timestamp(rest)
    hostname, rest = _parse_hostname(rest)
    tag, message = _parse_tag(rest)

    return SyslogMessage(
        priority=priority,
        facility=facility,
        severity=severity,
        facility_name=facility_name,
        severity_name=severity_name,
        timestamp=ts,
        hostname=hostname,
        tag=tag,
        message=message,
    )


def _parse_timestamp(s: str) -> Tuple[Optional[_dt.datetime], str]:
    """Parse a standard 15-character RFC 3164 timestamp (``Mmm DD HH:MM:SS``).

    This is the most common format and is fixed-width, so the split is
    cheap and unambiguous. Non-standard timestamp formats (ISO 8601,
    full year) are not supported. We return ``None`` when the year is
    absent, because choosing a year is a policy decision that depends on
    the caller's clock and context.
    """
    if len(s) >= 16 and s[3] == " " and s[6] == " " and s[9] == ":" and s[12] == ":":
        candidate = s[:15]
        try:
            naive = _dt.datetime.strptime(candidate, "%b %d %H:%M:%S")
            return naive.replace(tzinfo=_dt.timezone.utc), s[16:].lstrip(" ")
        except ValueError:
            pass
    return None, s


def _parse_hostname(s: str) -> Tuple[str, str]:
    """Parse a hostname token separated by a single space.

    RFC 3164 hostnames are restricted to alphanumeric plus ``.-_``.
    When the next token contains a character outside that set (such as a
    colon, which delimits a tag), we treat the hostname field as absent
    and leave the rest of the datagram to the tag/message parser.
    """
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    end = 0
    while end < len(s) and s[end] != " " and s[end] in allowed:
        end += 1
    if end == 0 or end >= len(s) or s[end] != " ":
        return "", s
    return s[:end], s[end + 1:]


def _parse_tag(s: str) -> Tuple[str, str]:
    """Parse the tag (process name and optional PID) and message body.

    We split on the first colon, take the alphanumeric run before it as
    the tag (optionally terminated by ``[PID]``), and treat everything
    after the colon as the message. When there is no colon, the entire
    remaining string is the tag and the message is empty.
    """
    colon = s.find(":")
    if colon == -1:
        return s, ""
    tag_part = s[:colon]
    bracket = tag_part.find("[")
    if bracket != -1 and tag_part.endswith("]"):
        tag_part = tag_part[:bracket]
    message_part = s[colon + 1:]
    if message_part.startswith(" "):
        message_part = message_part[1:]
    return tag_part, message_part
