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
    from sqlalchemy import create_engine, inspect
    from sqlalchemy.types import JSON

except Exception as err:
    print("pip3 install msticpy pandas whois redis requests click")


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
command_column = os.environ.get("COMMAND_COL", "COMMAND_LINE")
target_csv = sys.argv[1]

if not os.path.exists(target_csv):
    print(f"!! You have to provided a target csv to consume - file={target_csv}")
    exit(1)


if 'DB_BUILD' in os.environ:
    df_source = pd.read_csv(target_csv)
    df_source["cid"] = df_source[command_column].apply(
        lambda x: hashlib.md5(_parse_cmd(x).encode("utf8")).hexdigest()
    )
    df_source.to_sql('source', conn,
        if_exists="replace",
        dtype={}
    )

    fh = open("data/ioc_suspicious_commands.json", 'r')
    first_line = fh.readline()
    fh.close()
    record = json.loads(first_line)
    json_columns = df_json_columns(record)

    pd.read_json('data/ioc_suspicious_commands.json', lines=True).to_sql('suspicious_commands', conn,
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
    CREATE INDEX idx_suspicious_cid
    ON suspicious_commands (cid);
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



results = conn.execute(query)
for row in results:
    record = dict(row._mapping)
    print(record)
