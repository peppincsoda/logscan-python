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

import hyperscan


# Print all log messages to stderr
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler(sys.stderr))


def _hs_match(id_, from_, to, flags, scanner):
    scanner._hs_match(id_, from_, to, flags)


class Logscan:
    Regex = collections.namedtuple('Regex', 'id pattern flags')
    pattern_regex = re.compile(r'^(?P<id>.*):/(?P<pattern>.*)/(?P<flags>.*)$')

    def __init__(self, print_stats=False):
        self.print_stats = print_stats

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
                    if groups['id'] == 'prefix':
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
        if self.print_stats:
            log.info(f'PCRE compilation time (sec): {end - start}')

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
        if self.print_stats:
            log.info(f'Hyperscan DB compilation time (sec): {end - start}')

        if hs_db_file:
            log.info(f'Saving Hyperscan DB to disk: {hs_db_file}')
            with open(hs_db_file, 'wb') as f:
                f.write(hyperscan.dumps(self.hs_db))

    def compile_all(self, hs_db_file=None):
        self.compile_pcre()
        self.compile_hs(hs_db_file=hs_db_file)

    def scan(self, input, output):
        lineno = 0
        total_bytes = 0
        self._matched_lines = 0
        self._mismatched_ids = set()
        self.output = output

        start = time.time()
        while True:
            line = input.readline()
            if not line:
                break

            lineno += 1
            total_bytes += len(line)
            if self.prefix_regex:
                m = self.prefix_regex.match(line)
                if m:
                    line = m.group('details')

            self._line = line
            self.hs_db.scan(line, match_event_handler=_hs_match, context=self)
        end = time.time()

        if self._mismatched_ids:
            log.error('The following patterns were found by Hyperscan but did not match their PCREs:')
            log.error(', '.join(self._mismatched_ids))

        if self.print_stats:
            duration = end - start
            log.info(f'Total scanning time (sec): {duration}')
            log.info(f'Total number of lines: {lineno}')
            log.info(f'Total bytes: {total_bytes}')
            log.info(f'Average throughput (bytes/sec): {total_bytes / duration}')
            log.info(f'Total matched lines: {self._matched_lines}')

    def _hs_match(self, id_, from_, to, flags):
        m = self.compiled[id_].match(self._line)
        if m:
            d = {
                'id': self.regexes[id_].id,
            }
            d.update(m.groupdict())
            self.output.write(json.dumps(d) + '\n')
            self._matched_lines += 1
        else:
            self._mismatched_ids.add(self.regexes[id_].id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('patterns-file', help='Patterns file path')
    parser.add_argument('input-file', help='Input file path', nargs='*')
    parser.add_argument('-o', '--output-file', help='Output file path')
    parser.add_argument('--hs-db', help='Hyperscan DB file')
    parser.add_argument('--print-stats', help='print performance statistics', action='store_true')
    args = vars(parser.parse_args())

    try:
        log.info(args)
        scanner = Logscan(print_stats=args['print_stats'])
        scanner.load_patterns(args['patterns-file'])
        scanner.compile_all(hs_db_file=args['hs_db'])
        output_file = args['output_file']
        if output_file:
            output = open(output_file, 'w')
        else:
            output = sys.stdout

        input_files = args['input-file']
        if input_files:
            for input_file in input_files:
                with open(input_file, 'r') as input:
                    scanner.scan(input, output)
        else:
            scanner.scan(sys.stdin, output)

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
