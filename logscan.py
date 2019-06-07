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
import jsonschema
import yaml


# Print all log messages to stderr
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler(sys.stderr))


def _hs_match(id_, from_, to_, flags, scanner):
    # This code shall never raise exceptions
    # hyperscan will crash otherwise
    scanner._match_id = id_


class LogscanError(Exception):
    pass


class Logscan:
    PATTERNS_SCHEMA = 'patterns_schema.yaml'

    Regex = collections.namedtuple('Regex',
        'id pattern hs_flags pcre field_names field_types field_parsers',
    )

    def __init__(self, field_parser_creator):
        self.field_parser_creator = field_parser_creator
        self._field_parsers = {}

        self.mismatched_ids = {}
        self.stats = types.SimpleNamespace(
            pcre_compilation_time=0,
            hs_compilation_time=0,
            total_lines=0,
            total_bytes=0,
            matched_lines=0,
        )

    def load_patterns(self, patterns_file):
        self.regexes = []

        with open(patterns_file, 'r') as fp:
            conf = yaml.load(fp.read(), Loader=yaml.FullLoader)

        with open(os.path.join(os.path.dirname(__file__), self.PATTERNS_SCHEMA), 'r') as fp:
            patterns_schema = yaml.load(fp.read(), Loader=yaml.FullLoader)

        try:
            jsonschema.validate(
                conf,
                patterns_schema,
            )
        except jsonschema.exceptions.ValidationError as error:
            raise LogscanError(
                f'Validation of {patterns_file} failed against {self.PATTERNS_SCHEMA}: {error}'
            )

        prefix = conf.get('prefix', '')
        if type(prefix) is str:
            prefix_pattern = prefix
            prefix_fields = {}
        else:
            prefix_pattern = prefix['pattern']
            prefix_fields = prefix['fields']
        prefix_pattern = prefix_pattern.lstrip('^').rstrip('$')

        start = time.time()
        for id_, definition in conf['patterns'].items():
            if type(definition) is str:
                pattern = definition
                fields = {}
            else:
                pattern = definition['pattern']
                fields = definition['fields']

            pattern = pattern.lstrip('^').rstrip('$')
            pattern = '^%s$' % (prefix_pattern + pattern)

            fields = {**prefix_fields, **fields}

            pcre = re.compile(pattern)
            field_names = list(pcre.groupindex.keys())
            field_types = {
                name: fields[name]
                for name in field_names
                if name in fields
            }
            field_parsers = [
                self.get_field_parser(fields.get(name))
                for name in field_names
            ]

            self.regexes.append(self.Regex(
                id=id_,
                pattern=pattern,
                hs_flags=hyperscan.HS_FLAG_ALLOWEMPTY,
                pcre=pcre,
                field_names=field_names,
                field_types=field_types,
                field_parsers=field_parsers,
            ))
        self.stats.pcre_compilation_time = time.time() - start

    def get_field_parser(self, field_type):
        if field_type not in self._field_parsers:
            self._field_parsers[field_type] = self.field_parser_creator(field_type)

        return self._field_parsers[field_type]

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
            map(operator.itemgetter(self.Regex._fields.index('pattern')), self.regexes)
        ))
        ids = list(range(num_patterns))
        flags = list(map(operator.itemgetter(self.Regex._fields.index('hs_flags')), self.regexes))

        start = time.time()
        self.hs_db.compile(
            expressions=expressions,
            ids=ids,
            elements=num_patterns,
            flags=flags,
        )
        self.stats.hs_compilation_time = time.time() - start

        if hs_db_file:
            log.info(f'Saving Hyperscan DB to disk: {hs_db_file}')
            with open(hs_db_file, 'wb') as f:
                f.write(hyperscan.dumps(self.hs_db))

    def compile_all(self, hs_db_file=None):
        self.compile_hs(hs_db_file=hs_db_file)

    def scan(self, input):
        while True:
            line = input.readline()
            if not line:
                break

            self.stats.total_lines += 1
            self.stats.total_bytes += len(line)

            self._match_id = None
            self.hs_db.scan(line, match_event_handler=_hs_match, context=self)
            if self._match_id is not None:
                regex = self.regexes[self._match_id]
                m = regex.pcre.match(line)
                if m:
                    self.stats.matched_lines += 1

                    field_names = regex.field_names
                    field_parsers = regex.field_parsers

                    d = {
                        field_names[i]: field_parsers[i](m[i+1]) if field_parsers[i] else m[i+1]
                        for i in range(regex.pcre.groups)
                    }
                    d['id'] = regex.id
                    yield d

                else:
                    # Store only the first input line that had a mismatch
                    # Do not flood the output if there is an error with a pattern
                    if regex.id not in self.mismatched_ids:
                        self.mismatched_ids[regex.id] = self.stats.total_lines


def create_field_parser(field_type):
    if field_type == 'float':
        return lambda s: float(s)
    elif field_type == 'integer':
        return lambda s: int(s)

    # If `field_type` is empty or unknown, return None
    # In this case the value captured from the input line will not be parsed but returned as is


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

    scanner = Logscan(create_field_parser)
    try:
        scanner.load_patterns(args['patterns-file'])
    except LogscanError as error:
        log.error(error)
        return -1
    scanner.compile_all(hs_db_file=args['hs_db'])

    start = time.time()
    output_file = None
    try:
        output_file = args['output_file']
        if output_file:
            output = open(output_file, 'w')
        else:
            output = sys.stdout

        input_files = args['input-file']
        if input_files:
            for input_file in input_files:
                with open(input_file, 'r') as input:
                    printNDJSON(scanner.scan(input), output)
        else:
            printNDJSON(scanner.scan(sys.stdin), output)

    finally:
        if output_file:
            output.close()
    end = time.time()

    if scanner.mismatched_ids:
        log.error('The following patterns were found by Hyperscan but did not match their PCREs:')
        for id_, lineno in scanner.mismatched_ids.items():
            log.error(f'{id_} at line {lineno}')

    if args['print_stats']:
        duration = end - start
        log.info(f'PCRE compilation time (sec): {scanner.stats.pcre_compilation_time}')
        log.info(f'Hyperscan DB compilation time (sec): {scanner.stats.hs_compilation_time}')
        log.info(f'Total scanning time (sec): {duration}')
        log.info(f'Total number of lines: {scanner.stats.total_lines}')
        log.info(f'Total bytes: {scanner.stats.total_bytes}')
        log.info(f'Average throughput (bytes/sec): {scanner.stats.total_bytes / duration}')
        log.info(f'Total matched lines: {scanner.stats.matched_lines}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
