import datetime as dt
import unittest

from bsd_syslog_message_parser import parse, ParseError, SyslogMessage


class TestParse(unittest.TestCase):
    def test_full_message(self):
        msg = parse("<34>Oct 11 22:14:15 mymachine su: 'su root' failed")
        self.assertIsInstance(msg, SyslogMessage)
        self.assertEqual(msg.priority, 34)
        self.assertEqual(msg.facility, 4)
        self.assertEqual(msg.severity, 2)
        self.assertEqual(msg.facility_name, "auth")
        self.assertEqual(msg.severity_name, "crit")
        self.assertEqual(msg.timestamp, dt.datetime(1900, 10, 11, 22, 14, 15, tzinfo=dt.timezone.utc))
        self.assertEqual(msg.hostname, "mymachine")
        self.assertEqual(msg.tag, "su")
        self.assertEqual(msg.message, "'su root' failed")

    def test_single_digit_day(self):
        msg = parse("<13>Jan  1 00:00:00 host app: starting up")
        self.assertEqual(msg.timestamp, dt.datetime(1900, 1, 1, 0, 0, 0, tzinfo=dt.timezone.utc))

    def test_double_digit_day(self):
        msg = parse("<13>Jan 15 00:00:00 host app: starting up")
        self.assertEqual(msg.timestamp, dt.datetime(1900, 1, 15, 0, 0, 0, tzinfo=dt.timezone.utc))

    def test_tag_with_pid(self):
        msg = parse("<13>Jan 15 00:00:00 host app[1234]: starting up")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "starting up")

    def test_no_hostname_when_tag_follows(self):
        msg = parse("<13>Oct 11 22:14:15 app: hello")
        self.assertEqual(msg.hostname, "")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "hello")

    def test_no_hostname_when_tag_with_pid_follows(self):
        msg = parse("<13>Oct 11 22:14:15 app[42]: hello")
        self.assertEqual(msg.hostname, "")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "hello")

    def test_missing_timestamp(self):
        msg = parse("<13>app: no timestamp here")
        self.assertIsNone(msg.timestamp)
        self.assertEqual(msg.hostname, "")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "no timestamp here")

    def test_missing_hostname_and_timestamp(self):
        msg = parse("<13>app: bare message")
        self.assertIsNone(msg.timestamp)
        self.assertEqual(msg.hostname, "")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "bare message")

    def test_no_colon_means_empty_message(self):
        msg = parse("<13>Oct 11 22:14:15 host onlytag")
        self.assertEqual(msg.tag, "onlytag")
        self.assertEqual(msg.message, "")

    def test_priority_zero(self):
        msg = parse("<0>Oct 11 22:14:15 host app: msg")
        self.assertEqual(msg.facility, 0)
        self.assertEqual(msg.severity, 0)
        self.assertEqual(msg.facility_name, "kern")
        self.assertEqual(msg.severity_name, "emerg")

    def test_max_priority(self):
        msg = parse("<191>Oct 11 22:14:15 host app: msg")
        self.assertEqual(msg.facility, 23)
        self.assertEqual(msg.severity, 7)
        self.assertEqual(msg.facility_name, "local7")
        self.assertEqual(msg.severity_name, "debug")

    def test_message_with_colon(self):
        msg = parse("<13>Oct 11 22:14:15 host app: error: file not found")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "error: file not found")

    def test_localhost_hostname(self):
        msg = parse("<13>Oct 11 22:14:15 localhost app: hi")
        self.assertEqual(msg.hostname, "localhost")

    def test_fqdn_hostname(self):
        msg = parse("<13>Oct 11 22:14:15 host.example.com app: hi")
        self.assertEqual(msg.hostname, "host.example.com")

    def test_hostname_with_hyphen(self):
        msg = parse("<13>Oct 11 22:14:15 my-host app: hi")
        self.assertEqual(msg.hostname, "my-host")

    def test_hostname_with_underscore(self):
        msg = parse("<13>Oct 11 22:14:15 my_host app: hi")
        self.assertEqual(msg.hostname, "my_host")

    def test_message_with_ipv4_like_hostname(self):
        msg = parse("<13>Oct 11 22:14:15 192.168.1.1 app: hi")
        self.assertEqual(msg.hostname, "192.168.1.1")

    def test_missing_closing_angle(self):
        with self.assertRaises(ParseError):
            parse("<34Oct 11 22:14:15 host app: msg")

    def test_missing_opening_angle(self):
        with self.assertRaises(ParseError):
            parse("34>Oct 11 22:14:15 host app: msg")

    def test_empty_datagram(self):
        with self.assertRaises(ParseError):
            parse("")

    def test_priority_out_of_range(self):
        with self.assertRaises(ParseError):
            parse("<192>Oct 11 22:14:15 host app: msg")

    def test_non_string_datagram(self):
        with self.assertRaises(ParseError):
            parse(b"<34>Oct 11 22:14:15 host app: msg")  # type: ignore[arg-type]

    def test_timestamp_tz_aware(self):
        msg = parse("<34>Oct 11 22:14:15 mymachine su: hi")
        self.assertIsNotNone(msg.timestamp)
        self.assertEqual(msg.timestamp.tzinfo, dt.timezone.utc)

    def test_no_space_after_colon(self):
        msg = parse("<13>app:nospace")
        self.assertEqual(msg.tag, "app")
        self.assertEqual(msg.message, "nospace")

    def test_timestamp_no_year(self):
        msg = parse("<34>Oct 11 22:14:15 host app: hi")
        self.assertEqual(msg.timestamp, dt.datetime(1900, 10, 11, 22, 14, 15, tzinfo=dt.timezone.utc))

    def test_partial_timestamp_not_parsed(self):
        # A non-standard timestamp format should not be mistaken for a hostname.
        msg = parse("<13>2023-01-01T00:00:00Z app: hi")
        self.assertIsNone(msg.timestamp)
        self.assertEqual(msg.hostname, "")
        self.assertEqual(msg.tag, "2023-01-01T00")
        self.assertEqual(msg.message, "00:00Z app: hi")


if __name__ == "__main__":
    unittest.main()
