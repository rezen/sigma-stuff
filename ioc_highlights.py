#!/usr/bin/env python3

import os
import re
import csv
import sys
import json
import hashlib
import os.path

try:
    import pandas as pd
    from sqlalchemy import create_engine, inspect, Table, Column, Integer, String, MetaData, Boolean, UniqueConstraint, insert
    from sqlalchemy.types import JSON

except Exception as err:
    print(err)
    print("pip3 install msticpy pandas whois redis requests click")
    exit(1)


def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        d[column.name] = str(getattr(row, column.name))
    return d

def df_json_columns(df):
    if isinstance(df, pd.DataFrame):
        data = df.to_dict()
    else:
        data = df

    json_columns = []
    for key in data:
        if isinstance(data[key], list):
            json_columns.append(key)
        elif isinstance(data[key], dict):
            json_columns.append(key)
    return json_columns


def _parse_cmd(x):
    # The data is not always valid json so let's strip out the json prefix
    prefix = r'^{["]+command["]+:["]+'
    x = re.sub(prefix, "", x)
    return x.rstrip('""}').replace('""', '"').strip()


engine = create_engine("sqlite:///data/dataset.db")
conn = engine.connect()
session = conn
command_column = os.environ.get("COMMAND_COL", "COMMAND_LINE")
target_csv = sys.argv[1]

if not os.path.exists(target_csv):
    print(f"!! You have to provided a target csv to consume - file={target_csv}")
    exit(1)



meta = MetaData()
status_table = Table(
    'command_status', meta,
    Column('cid', String, index=True, unique=True),
    Column('is_comprimised', Boolean, nullable=True),
    Column('is_false_positive', Boolean),
    Column('status', String),
)

try:
    meta.create_all(engine)
except:
    pass


if 'DB_BUILD' in os.environ:
    df_source = pd.read_csv(target_csv)
    df_source["cid"] = df_source[command_column].apply(
        lambda x: hashlib.md5(_parse_cmd(x).encode("utf8")).hexdigest()
    )
    df_source.to_sql('source', conn,
        if_exists="replace",
        dtype={}
    )

    fh = open("data/commands_parsed.json", 'r')
    first_line = fh.readline()
    fh.close()
    record = json.loads(first_line)
    json_columns = df_json_columns(record)

    df_status = pd.DataFrame([])
    df_suspicious = pd.read_json('data/commands_parsed.json', lines=True)
    cids = df_suspicious['cid'].tolist()

    for cid in cids:
        try:
            stmt = insert(status_table).values(cid=cid)
            engine.execute(stmt)
        except:
            pass

    df_suspicious['is_comprimised'] = None
    df_suspicious.to_sql('commands_parsed', conn,
        if_exists="replace",
        dtype={
            # Needs help complex datatypes ... objects/lists
            c: JSON for c in json_columns
        }
    )


    pd.read_csv('data/iocs.csv').to_sql('iocs', conn,
        if_exists="replace",
        dtype={}
    )
    pd.read_csv("data/ioc_facts.csv").to_sql('ioc_facts', conn,
        if_exists="replace",
        dtype={}
    )
    pd.read_csv("data/sigma_matches.csv").to_sql('sigma_matches', conn,
        if_exists="replace",
        dtype={}
    )

"""
inspector = inspect(engine)
schemas = inspector.get_schema_names()
for schema in schemas:
    print("schema: %s" % schema)
    for table_name in inspector.get_table_names(schema=schema):
        for column in inspector.get_columns(table_name, schema=schema):
            print("Column: %s" % column)
"""

try:

    query = '''
    CREATE INDEX idx_command_status_cid
    ON command_status (cid);
    '''.strip()
    conn.execute(query)


    query = '''
    CREATE INDEX idx_commands_parsed_cid
    ON commands_parsed (cid);
    '''.strip()
    conn.execute(query)


    query = '''
    CREATE INDEX idx_iocs_facts_ioc
    ON ioc_facts (ioc);
    '''.strip()
    conn.execute(query)

    query = '''
    CREATE INDEX idx_iocs_facts_key
    ON ioc_facts (key);
    '''.strip()
    conn.execute(query)


    query = '''
    CREATE INDEX idx_sigma_cid
    ON sigma_matches (cid);
    '''.strip()
    conn.execute(query)


    query = '''
    CREATE INDEX idx_source_cid
    ON source (cid);
    '''.strip()
    conn.execute(query)

    query = '''
    CREATE INDEX idx_iocs_cid
    ON iocs (cid);
    '''.strip()
    conn.execute(query)
except Exception as err:
    pass

query = '''
SELECT source.cid, count(m.cid) as sigma_count, count(iocs.cid) as ioc_count
FROM source
LEFT JOIN
    iocs on iocs.cid = source.cid
LEFT JOIN
    sigma_matches m on m.cid = source.cid
GROUP BY
    source.cid
ORDER BY
    count(m.cid) DESC
'''.strip()

query = '''
SELECT source.cid, count(m.cid) as sigma_count, count(iocs.cid) as ioc_count
FROM source
LEFT JOIN
    iocs on iocs.cid = source.cid
LEFT JOIN
    sigma_matches m on m.cid = source.cid
GROUP BY
    source.cid
ORDER BY
    count(m.cid) DESC
'''.strip()

#
query = '''
SELECT m.level, m.rule, source.ORGANIZATION_ID, m.cid, source.COMMAND_LINE
FROM sigma_matches m
JOIN
    source on source.cid = m.cid
WHERE m.level in ('medium', 'high')

'''.strip()

fh = open("data/sigmas_high.csv", "w+")
writer = csv.DictWriter(fh, [
    'level', 'rule',
    'organization_id'.upper(), 'cid',
    'command_line'.upper(), 'details'.upper()
])
writer.writeheader()


results = conn.execute(query)
for row in results:
    record = dict(row._mapping)
    writer.writerow(record)

fh.close()