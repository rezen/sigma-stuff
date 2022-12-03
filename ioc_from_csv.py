#!/usr/bin/env python3
# Point this script at a csv that has a column with command line data and parse through
# and augment data with ioc data
#
# COMMAND_COL=DETAILS ./ioc_from_csv.py  ~/Downloads/result_simple_unique.csv
from functools import cache
import sys
import re
import json
import os.path
import hashlib

try:
    import pandas as pd
    import msticpy as mp

    from msticpy.transform import IoCExtract, base64unpack
    from msticpy.context.geoip import GeoLiteLookup, IPStackLookup
except Exception as err:
    print("pip3 install msticpy pandas")

try:
    import sigma_windows_proc_rules
except:
    print("You need this file to execute sigmas rules!")
    print("https://github.com/rezen/sigma-stuff/blob/main/sigma_windows_proc_rules.py")


class Stringy(str):
    # Sigma rules use this contains function ... so extend string for that
    def contains(self, x):
        return x in self


def _parse_cmd(x):
    # The data is not always valid json so let's strip out the json prefix
    prefix = r'^{["]+command["]+:["]+'
    x = re.sub(prefix, "", x)
    return x.rstrip('""}').replace('""', '"').strip()


def _parse_image(x):
    # For some sigmas rules they want image. This is an attempt to backfill that.
    # needs lots of love
    if x.startswith("cmd /C"):
        x = x.lstrip("cmd /C")
    return x.split(" ").pop(0)


def get_ioc_extractor():
    extractor = IoCExtract()
    # extractor.add_ioc_type(ioc_type="win_named_pipe", ioc_regex=r"(?P<pipe>\\\\\.\\pipe\\[^\s\\]+)")
    # extractor.add_ioc_type(ioc_type="cyrillic_chars", ioc_regex=r"([А-Яа-яЁё]+)")
    return extractor


def get_sigmas_matches(command: str):
    matches = []
    for method in sigma_windows_proc_rules.CLI_ONLY_COMPAT_METHODS:
        try:
            is_match = getattr(sigma_windows_proc_rules, method)(
                {
                    "_raw": Stringy(command),
                    "COMMAND_LINE": Stringy(command),
                }
            )
            if is_match:
                continue
            matches.append(method)
        except Exception as err:
            pass
    return matches


@cache
def command_to_ioc_data(command: str):
    # Cleanup invalid json bits in command
    command = _parse_cmd(command)
    iplocation = GeoLiteLookup()
    extractor = get_ioc_extractor()
    iocs = extractor.extract(command)
    record = {
        "cid": hashlib.md5(command.encode("utf8")).hexdigest(),
        "image": _parse_image(command),
        "command_line": command,
        "sigma_matches": get_sigmas_matches(command),
        "iocs_ipv4": list(iocs.get("ipv4", set())),
        "iocs_dns": list(iocs.get("dns", set())),
        "iocs_ipv4_countries": set(),
    }

    for ip in record["iocs_ipv4"]:
        loc_result, ip_entity = iplocation.lookup_ip(ip_address=ip)
        country = loc_result.pop().get("country", {}).get("iso_code")
        if not country:
            continue

        record["iocs_ipv4_countries"].add(country)
    record["iocs_ipv4_countries"] = list(record["iocs_ipv4_countries"])
    record["iocs_network_count"] = len(record["iocs_ipv4"]) + len(record["iocs_dns"])
    record["sigma_matches_count"] = len(record["sigma_matches"])
    return record


target_csv = sys.argv[1]
if not os.path.exists(target_csv):
    print(f"!! You have to provided a target csv to consume - file={target_csv}")
    exit(1)


command_column = os.environ.get("COMMAND_COL", "DETAILS")
print(f" - Reading file={target_csv} col={command_column} to as columns for commands")

df_source = pd.read_csv(target_csv)
df_source["CommandLine"] = df_source[command_column].apply(_parse_cmd)
df_source["cid"] = df_source["CommandLine"].apply(
    lambda x: hashlib.md5(x.encode("utf8")).hexdigest()
)


ioc_records = []
with open("ioc_data.json", "w+") as fh:
    for command in df_source["CommandLine"].tolist():
        if not command:
            continue
        data = command_to_ioc_data(command)
        ioc_records.append(data)
        fh.write(json.dumps(data, default=str) + "\n")

# @todo glue in iocs data with df_source
# df_iocs = pd.DataFrame(ioc_records)
