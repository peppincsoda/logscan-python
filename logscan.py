import argparse
import collections
import functools
import json
import logging
import operator
import os
import re
import sys
import time
import traceback
import types

import hyperscan


PREFIX_ID = 'prefix'
PREFIX_DETAILS = 'details'


# Print all log messages to stderr
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler(sys.stderr))


def _hs_match(id_, from_, to, flags, scanner):
    scanner._hs_match(id_, from_, to, flags)


class Logscan:
    Regex = collections.namedtuple('Regex', 'id pattern flags')
    pattern_regex = re.compile(r'^(?P<id>.*):/(?P<pattern>.*)/(?P<flags>.*)$')

    def __init__(self):
        self.mismatched_ids = set()
        self.stats = types.SimpleNamespace(
            pcre_compilation_time=0,
            hs_compilation_time=0,
            total_lines=0,
            total_bytes=0,
            matched_lines=0,
        )

    def load_patterns(self, patterns_file):
        self.regexes = []
        self.prefix_regex = None

        with open(patterns_file, 'r') as f:
            lineno = 0
            while True:
                line = f.readline()
                if not line:
                    break

                lineno += 1
                if line[0] == '\n' or line[0] == '#':
                    continue

                m = self.pattern_regex.match(line)
                if m:
                    groups = m.groupdict()
                    if groups['id'] == PREFIX_ID:
                        self.prefix_regex = re.compile(groups['pattern'])
                    else:
                        groups['flags'] = hyperscan.HS_FLAG_ALLOWEMPTY
                        self.regexes.append(self.Regex(**groups))
                else:
                    log.error(f'Invalid pattern format at {patterns_file}:{lineno}')

    def compile_pcre(self):
        start = time.time()
        self.compiled = [
            re.compile(regex.pattern)
            for regex in self.regexes
        ]
        end = time.time()
        self.stats.pcre_compilation_time = end - start

    def compile_hs(self, hs_db_file=None):
        if hs_db_file and os.path.isfile(hs_db_file):
            log.info(f'Loading Hyperscan DB from disk: {hs_db_file}')
            with open(hs_db_file, 'rb') as f:
                self.hs_db = hyperscan.loads(bytearray(f.read()))
            return

        self.hs_db = hyperscan.Database()

        num_patterns = len(self.regexes)
        expressions = list(map(
            functools.partial(str.encode, encoding='utf-8'),
            map(operator.itemgetter(self.Regex._fields.index('pattern')), self.regexes))
        )
        ids = list(range(num_patterns))
        flags = list(map(operator.itemgetter(self.Regex._fields.index('flags')), self.regexes))

        start = time.time()
        self.hs_db.compile(
            expressions=expressions,
            ids=ids,
            elements=num_patterns,
            flags=flags,
        )
        end = time.time()
        self.stats.hs_compilation_time = end - start

        if hs_db_file:
            log.info(f'Saving Hyperscan DB to disk: {hs_db_file}')
            with open(hs_db_file, 'wb') as f:
                f.write(hyperscan.dumps(self.hs_db))

    def compile_all(self, hs_db_file=None):
        self.compile_pcre()
        self.compile_hs(hs_db_file=hs_db_file)

    def scan(self, input):
        while True:
            line = input.readline()
            if not line:
                break

            self.stats.total_lines += 1
            self.stats.total_bytes += len(line)
            if self.prefix_regex:
                m = self.prefix_regex.match(line)
                if m:
                    line = m.group(PREFIX_DETAILS)

            self._line = line
            self.hs_db.scan(line, match_event_handler=_hs_match, context=self)
            if self._match:
                yield self._match

    def _hs_match(self, id_, from_, to, flags):
        m = self.compiled[id_].match(self._line)
        if m:
            d = {
                'id': self.regexes[id_].id,
            }
            d.update(m.groupdict())
            self.stats.matched_lines += 1
            self._match = d
        else:
            self.mismatched_ids.add(self.regexes[id_].id)
            self._match = None


def printNDJSON(input, output):
    for match in input:
        output.write(json.dumps(match) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('patterns-file', help='Patterns file path')
    parser.add_argument('input-file', help='Input file path', nargs='*')
    parser.add_argument('-o', '--output-file', help='Output file path')
    parser.add_argument('--hs-db', help='Hyperscan DB file')
    parser.add_argument('--print-stats', help='print performance statistics', action='store_true')
    args = vars(parser.parse_args())

    output_file = None
    try:
        scanner = Logscan()
        scanner.load_patterns(args['patterns-file'])
        scanner.compile_all(hs_db_file=args['hs_db'])

        output_file = args['output_file']
        if output_file:
            output = open(output_file, 'w')
        else:
            output = sys.stdout

        start = time.time()
        input_files = args['input-file']
        if input_files:
            for input_file in input_files:
                with open(input_file, 'r') as input:
                    printNDJSON(scanner.scan(input), output)
        else:
            printNDJSON(scanner.scan(sys.stdin), output)
        end = time.time()

        if scanner.mismatched_ids:
            log.error('The following patterns were found by Hyperscan but did not match their PCREs:')
            log.error(', '.join(scanner.mismatched_ids))

        if args['print_stats']:
            duration = end - start
            log.info(f'PCRE compilation time (sec): {scanner.stats.pcre_compilation_time}')
            log.info(f'Hyperscan DB compilation time (sec): {scanner.stats.hs_compilation_time}')
            log.info(f'Total scanning time (sec): {duration}')
            log.info(f'Total number of lines: {scanner.stats.total_lines}')
            log.info(f'Total bytes: {scanner.stats.total_bytes}')
            log.info(f'Average throughput (bytes/sec): {scanner.stats.total_bytes / duration}')
            log.info(f'Total matched lines: {scanner.stats.matched_lines}')

    except Exception:
        # hyperscan crashes Python if an exception escapes, that's why everything is catched here
        log.error(traceback.format_exc())
        return -1

    finally:
        if output_file:
            output.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
