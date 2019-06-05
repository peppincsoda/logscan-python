import argparse
import sys

import elasticsearch_dsl as es_dsl
from elasticsearch import helpers
from logscan import Logscan, log


INDEX_PREFIX = 'logscan'


def connect_elasticsearch(url):
    return es_dsl.connections.create_connection(hosts=[url], timeout=20)


def add_field_mappings(id_, regex, mapping):
    for group_name in regex.groupindex.keys():
        try:
            field_name, field_type = group_name.split(':')
        except ValueError:
            field_name = group_name
            field_type = 'text'

        if id_ != 'prefix' or field_name != 'details': # TODO: constant
            mapping.field(field_name, field_type)


def create_indices(scanner):
    for i, regex in enumerate(scanner.compiled):
        id_ = scanner.regexes[i].id

        index_name = f'{INDEX_PREFIX}-{id_}'
        index = es_dsl.Index(index_name)
        if index.exists():
            index.delete()
        index.create()

        mapping = es_dsl.Mapping()
        if scanner.prefix_regex:
            add_field_mappings('prefix', scanner.prefix_regex, mapping)
        add_field_mappings(id_, regex, mapping)
        mapping.save(index_name)


def gendata_for_bulk(input):
    for event in input:
        yield {
            '_index': f'{INDEX_PREFIX}-{event["id"]}',
            'doc': event,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='Elasticsearch endpoint URL')
    parser.add_argument('patterns_file', help='Patterns file path')
    parser.add_argument('input_file', help='Input file path', nargs='?')
    parser.add_argument('--hs-db', help='Hyperscan DB file')
    args = parser.parse_args()

    scanner = Logscan()
    scanner.load_patterns(args.patterns_file)
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
