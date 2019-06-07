import argparse
import datetime
import re
import sys

import elasticsearch_dsl as es_dsl
from elasticsearch import helpers
from logscan import Logscan, LogscanError, log


INDEX_PREFIX = 'logscan'
ES_DATE_REGEX = re.compile(r'^es_date\((?P<format>.*)\)$')


def create_field_parser(field_type):
    # Default type is 'text'; no parsing required
    if not field_type:
        return None

    m = ES_DATE_REGEX.match(field_type)
    if m:
        format_ = m.group('format')

        # Parses datetime using strptime and returns milliseconds since epoch in UTC as integer
        def es_date(value):
            dt = datetime.datetime.strptime(value, format_)
            return int(dt.timestamp() * 1000)

        return es_date


def connect_elasticsearch(url):
    return es_dsl.connections.create_connection(hosts=[url], timeout=20)


def add_field_mappings(id_, regex, mapping):
    for field_name in regex.field_names:
        field_type = regex.field_types.get(field_name)

        # Map types to Elasticsearch types
        if not field_type:
            field_type = 'text' # Default type is 'text'
        elif ES_DATE_REGEX.match(field_type):
            field_type = 'date'

        mapping.field(field_name, field_type)


def create_indices(scanner):
    for regex in scanner.regexes:
        id_ = regex.id.lower()

        index_name = f'{INDEX_PREFIX}-{id_}'.lower()
        index = es_dsl.Index(index_name)
        if index.exists():
            index.delete()
        index.create()

        mapping = es_dsl.Mapping()
        add_field_mappings(id_, regex, mapping)
        mapping.save(index_name)


def gendata_for_bulk(input):
    for event in input:
        id_ = event['id']
        index_name = f'{INDEX_PREFIX}-{id_}'.lower()
        yield {
            **event,
            '_index': index_name,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='Elasticsearch endpoint URL')
    parser.add_argument('patterns_file', help='Patterns file path')
    parser.add_argument('input_file', help='Input file path', nargs='?')
    parser.add_argument('--hs-db', help='Hyperscan DB file')
    args = parser.parse_args()

    scanner = Logscan(create_field_parser)
    try:
        scanner.load_patterns(args.patterns_file)
    except LogscanError as error:
        log.error(error)
        return -1
    scanner.compile_all(hs_db_file=args.hs_db)

    es_conn = connect_elasticsearch(args.url)
    create_indices(scanner)

    if args.input_file:
        with open(args.input_file, 'r') as input:
            helpers.bulk(es_conn, gendata_for_bulk(scanner.scan(input)))
    else:
        helpers.bulk(es_conn, gendata_for_bulk(scanner.scan(sys.stdin)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
