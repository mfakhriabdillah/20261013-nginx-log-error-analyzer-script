```python
#!/usr/bin/env python3
"""Nginx Log Error Analyzer - CLI tool for cloud/DevOps engineers."""

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Regex patterns for common Nginx error log formats
ERROR_LOG_PATTERNS = [
    # Standard error log format: timestamp [level] pid#tid: *cid message, client: ..., server: ..., request: "..."
    re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>[^\]]+)\]\s+'
        r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
        r'(?P<connection>\*\d+)\s+'
        r'(?P<message>.+)$'
    ),
    # Format without connection id: timestamp [level] pid#tid: message
    re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>[^\]]+)\]\s+'
        r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
        r'(?P<message>.+)$'
    ),
]

REQUEST_RE = re.compile(r',\s*client:\s*([^,]+)')
SERVER_RE = re.compile(r',\s*server:\s*([^,]+)')
REQUEST_HEADER_RE = re.compile(r',\s*request:\s*"([^"]*)"')


class LogEntry:
    """Parsed Nginx error log entry."""

    __slots__ = ('timestamp', 'level', 'pid', 'tid', 'connection',
                 'message', 'client_ip', 'server', 'request', 'raw_line')

    def __init__(self, timestamp: datetime, level: str, pid: int,
                 tid: int, connection: str, message: str,
                 client_ip: Optional[str], server: Optional[str],
                 request: Optional[str], raw_line: str):
        self.timestamp = timestamp
        self.level = level
        self.pid = pid
        self.tid = tid
        self.connection = connection
        self.message = message
        self.client_ip = client_ip
        self.server = server
        self.request = request
        self.raw_line = raw_line

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'pid': self.pid,
            'tid': self.tid,
            'connection': self.connection,
            'message': self.message,
            'client_ip': self.client_ip,
            'server': self.server,
            'request': self.request,
        }


class LogParser:
    """Parses Nginx error log lines into LogEntry objects."""

    @staticmethod
    def parse_line(line: str) -> Optional[LogEntry]:
        """Parse a single log line, extracting message components."""
        line = line.strip()
        if not line:
            return None

        pattern = None
        for p in ERROR_LOG_PATTERNS:
            m = p.match(line)
            if m:
                pattern = p
                break

        if pattern is None:
            logger.debug("Unparseable line: %s", line[:120])
            return None

        groups = {k: v for k, v in m.groupdict().items()}

        try:
            ts = datetime.strptime(groups['timestamp'], '%Y/%m/%d %H:%M:%S')
        except ValueError:
            logger.debug("Bad timestamp in line: %s", line[:120])
            return None

        client_ip = None
        server = None
        request = None
        msg = groups['message']

        cm = REQUEST_RE.search(msg)
        if cm:
            client_ip = cm.group(1).strip()

        sm = SERVER_RE.search(msg)
        if sm:
            server = sm.group(1).strip()

        rm = REQUEST_HEADER_RE.search(msg)
        if rm:
            request = rm.group(1)

        return LogEntry(
            timestamp=ts,
            level=groups['level'],
            pid=int(groups['pid']),
            tid=int(groups['tid']),
            connection=groups['connection'],
            message=msg,
            client_ip=client_ip,
            server=server,
            request=request,
            raw_line=line,
        )

    @staticmethod
    def parse_file(path: Path, skip_errors: bool = True) -> Iterator[LogEntry]:
        """Yield LogEntry objects from a log file."""
        total = 0
        skipped = 0
        with path.open('r', encoding='utf-8', errors='replace') as fh:
            for lineno, raw in enumerate(fh, start=1):
                total += 1
                entry = LogParser.parse_line(raw)
                if entry is not None:
                    yield entry
                else:
                    skipped += 1
                    if not skip_errors:
                        logger.warning("Line %d unparsed: %s", lineno, raw[:120])
        logger.info("Parsed %d lines, skipped %d unparseable.", total, skipped)


class StatsAggregator:
    """Aggregates statistics from parsed log entries."""

    def __init__(self) -> None:
        self.level_counts: Counter = Counter()
        self.message_counts: Counter = Counter()
        self.client_counts: Counter = Counter()
        self.server_counts: Counter = Counter()
        self.hourly_counts: Counter = Counter()
        self.entries: List[LogEntry] = []

    def feed(self, entry: LogEntry) -> None:
        """Update aggregations with a single entry."""
        self.level_counts[entry.level] += 1
        self.message_counts[entry.message] += 1
        if entry.client_ip:
            self.client_counts[entry.client_ip] += 1
        if entry.server:
            self.server_counts[entry.server] += 1
        self.hourly_counts[entry.timestamp.strftime('%Y-%m-%d %H:00')] += 1
        self.entries.append(entry)

    def summary(self, top_n: int = 10) -> Dict[str, Any]:
        """Return a dictionary of aggregated statistics."""
        total = sum(self.level_counts.values())
        return {
            'total_entries': total,
            'level_breakdown': dict(self.level_counts.most_common()),
            'top_messages': [
                {'message': msg, 'count': cnt}
                for msg, cnt in self.message_counts.most_common(top_n)
            ],
            'top_clients': [
                {'ip': ip, 'count': cnt}
                for ip, cnt in self.client_counts.most_common(top_n)
            ],
            'top_servers': [
                {'server': s, 'count': cnt}
                for s, cnt in self.server_counts.most_common(top_n)
            ],
            'hourly_distribution': dict(
                sorted(self.hourly_counts.items())
            ),
        }

    def filter_by_level(self, levels: List[str]) -> 'StatsAggregator':
        """Return a new aggregator filtered to specific log levels."""
        agg = StatsAggregator()
        for entry in self.entries:
            if entry.level in levels:
                agg.feed(entry)
        return agg

    def filter_by_time_range(
        self, start: Optional[datetime], end: Optional[datetime]
    ) -> 'StatsAggregator':
        """Return a new aggregator filtered to a time window."""
        agg = StatsAggregator()
        for entry in self.entries:
            if start and entry.timestamp < start:
                continue
            if end and entry.timestamp > end:
                continue
            agg.feed(entry)
        return agg


def parse_timestamp(ts_str: str) -> datetime:
    """Parse a timestamp string in various common formats."""
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ'):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"Unrecognized timestamp format: {ts_str!r}")


def build_argument_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog='nginx-error-analyzer',
        description='Analyze Nginx error logs for cloud/DevOps workflows.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        'input',
        nargs='?',
        type=Path,
        default=Path('-'),
        help='Path to Nginx error log file (default: stdin)',
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=None,
        help='Write results to this file (default: stdout)',
    )
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'text'],
        default='text',
        help='Output format (default: text)',
    )
    parser.add_argument(
        '-l', '--level',
        nargs='+',
        choices=['debug', 'info', 'notice', 'warn', 'error', 'crit',
                 'alert', 'emerg'],
        default=None,
        metavar='LEVEL',
        help='Filter by one or more log levels',
    )
    parser.add_argument(
        '--start',
        type=parse_timestamp,
        default=None,
        metavar='DATETIME',
        help='Include entries after this timestamp',
    )
    parser.add_argument(
        '--end',
        type=parse_timestamp,
        default=None,
        metavar='DATETIME',
        help='Include entries before this timestamp',
    )
    parser.add_argument(
        '-n', '--top-n',
        type=int,
        default=10,
        metavar='N',
        help='Number of top entries to show (default: 10)',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable debug logging',
    )
    parser.add_argument(
        '--no-skip',
        action='store_true',
        help='Do not skip unparseable lines (print warnings)',
    )
    return parser


def format_text(summary: Dict[str, Any], top_n: int) -> str:
    """Render summary as human-readable text."""
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("  Nginx Error Log Analysis Report")
    lines.append("=" * 60)
    lines.append(f"  Total entries analyzed : {summary['total_entries']}")
    lines.append("")

    lines.append("  Level Breakdown:")
    lines.append("  " + "-" * 40)
    for level, count in summary['level_breakdown'].items():
        pct = count / summary['total_entries'] * 100 if summary['total_entries'] else 0
        lines.append(f"    {level:>6s}  {count:>8d}  ({pct:5.1f}%)")
    lines.append("")

    lines.append("  Top Error Messages:")
    lines.append("  " + "-" * 40)
    for item in summary['top_messages'][:top_n]:
        lines.append(f"    [{item['count']:>5d}] {item['message'][:80]}")
    lines.append("")

    lines.append("  Top Client IPs:")
    lines.append("  " + "-" * 40)
    for item in summary['top_clients'][:top_n]:
        lines.append(f"    {item['ip']:>20s}  {item['count']:>6d}")
    lines.append("")

    lines.append("  Top Servers:")
    lines.append("  " + "-" * 40)
    for item in summary['top_servers'][:top_n]:
        lines.append(f"    {item['server']:>25s}  {item['count']:>6d}")
    lines.append("")

    lines.append("  Hourly Distribution:")
    lines.append("  " + "-" * 40)
    for hour, count in list(summary['hourly_distribution'].items())[:20]:
        bar = "█" * (count // 5) if count else ""
        lines.append(f"    {hour}  {count:>5d}  {bar}")
    if len(summary['hourly_distribution']) > 20:
        lines.append(f"    ... ({len(summary['hourly_distribution']) - 20} more hours)")
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def format_csv(summary: Dict[str, Any], top_n: int, out) -> None:
    """Write summary as CSV to the given text stream."""
    writer = csv.writer(out)
    writer.writerow(['metric', 'key', 'value'])
    writer.writerow(['total_entries', '', summary['total_entries']])
    for level, count in summary['level_breakdown'].items():
        writer.writerow(['level', level, count])
    for item in summary['top_messages'][:top_n]:
        writer.writerow(['top_message', item['message'][:100], item['count']])
    for item in summary['top_clients'][:top_n]:
        writer.writerow(['top_client', item['ip'], item['count']])
    for item in summary['top_servers'][:top_n]:
        writer.writerow(['top_server', item['server'], item['count']])
    for hour, count in summary['hourly_distribution'].items():
        writer.writerow(['hourly', hour, count])


def format_json(summary: Dict[str, Any], top_n: int, out) -> None:
    """Write summary as JSON to the given text stream."""
    json.dump(summary, out, indent=2, default=str)
    out.write("\n")


def run(args: argparse.Namespace) -> int:
    """Core analysis logic; returns exit code."""
    agg = StatsAggregator()

    source = args.input
    if source == Path('-'):
        logger.info("Reading from stdin.")
        entries = (LogParser.parse_line(line) for line in sys.stdin)
    else:
        if not source.exists():
            logger.error("Input file not found: %s", source)
            return 2
        if not source.is_file():
            logger.error("Input path is not a file: %s", source)
            return 2
        logger.info("Reading log file: %s", source)
        entries = LogParser.parse_file(source, skip_errors=not args.no_skip)

    for entry in entries:
        if entry is None:
            continue
        agg.feed(entry)

    if args.level:
        agg = agg.filter_by_level(args.level)

    if args.start or args.end:
        agg = agg.filter_by_time_range(args.start, args.end)

    summary = agg.summary(top_n=args.top_n)

    if args.format == 'json':
        formatter = lambda out: format_json(summary, args.top_n, out)
    elif args.format == 'csv':
        formatter = lambda out: format_csv(summary, args.top_n, out)
    else:
        formatter = lambda out: print(format_text(summary, args.top_n), file=out)

    if args.output:
        with args.output.open('w', encoding='utf-8') as fh:
            formatter(fh)
        logger.info("Results written to %s", args.output)
    else:
        formatter(sys.stdout)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for the CLI."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    try:
        return run(args)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        return 130
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```