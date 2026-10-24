# bsd-syslog-message-parser

Parses RFC 3164 BSD syslog datagrams into priority, facility, severity, timestamp, hostname, tag, and message fields.

## Installation

This library has zero third-party dependencies. Install it with pip:

```bash
pip install bsd-syslog-message-parser
```

## Usage

```python
from bsd_syslog_message_parser import parse, SyslogMessage, ParseError

try:
    msg = parse("<34>Oct 11 22:14:15 mymachine su: 'su root' failed")
except ParseError as e:
    # handle malformed input
    raise

print(msg.priority)        # 34
print(msg.facility)        # 4
print(msg.severity)        # 2
print(msg.facility_name)   # "auth"
print(msg.severity_name)   # "crit"
print(msg.timestamp)       # datetime(1900, 10, 11, 22, 14, 15, tzinfo=UTC)
print(msg.hostname)        # "mymachine"
print(msg.tag)             # "su"
print(msg.message)         # "'su root' failed"
```

## Why this exists

RFC 3164 is the legacy BSD syslog format still emitted by the majority of network appliances and Unix daemons. It is underspecified: the year is absent from the timestamp, the hostname is optional, and the boundary between the tag and the message is implicit. This library provides a single, focused parser that makes one clear decision for each ambiguity rather than trying to satisfy conflicting interpretations.

The specific trade-off: this parser handles only the standard 15-character timestamp (`Mmm DD HH:MM:SS`). It does not support ISO 8601, full dates, or millisecond variants. If your inputs use a non-standard timestamp, the parser returns `timestamp=None` and does not attempt to guess.

## Edge cases

- **Year inference**: RFC 3164 timestamps omit the year. Rather than invent one, `timestamp` is `None` when the year cannot be determined. If you need a year, supply your own clock logic in the caller.
- **Hostname vs. tag**: The hostname field is restricted to alphanumeric characters plus `.`, `-`, and `_`. When the token after the timestamp contains a character outside that set (such as a colon, which delimits the tag), it is treated as the tag, not the hostname.
- **Tag with PID**: Tags like `app[1234]` are normalized to `app`.
- **Priority range**: Priorities outside `[0, 191]` raise `ParseError`.

## Running the tests

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## License

MIT
