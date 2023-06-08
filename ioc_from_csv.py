#!/usr/bin/env python3
# Point this script at a csv that has a column with command line data and parse through
# and augment data with ioc data
#
# For per persistent caching use redis to speed things up!
# docker run -d --name redis-stack-server -p 6379:6379 redis/redis-stack-server:latest
#
# COMMAND_COL=DETAILS ./ioc_from_csv.py  ~/Downloads/result_simple_unique.csv
#
# We should probably seed sqlite tables from this queries to make it easy to connect data


# ioc_all_records (Full dataset)

# sigma_matches (For each instance of a sigma rule execution against a given command)
# cid,rule,level
# 2e69c80ae835bbca4cddbb3888bb9dda,sigma_usage_of_web_request_commands_and_cmdlets,medium

# iocs (Each individual ioc found for each command)
# cid, type, value
# 2e69c80ae835bbca4cddbb3888bb9dda,dns,screenshare.tech
# 2e69c80ae835bbca4cddbb3888bb9dda,ip,8.8.8.8

# ioc_facts (Additional context or facts from iocs)
# ioc, key, value
# screenshare.tech,age,7
# screenshare.tech,age,7

import sys
import re
import csv
import json
import os.path
import hashlib
from datetime import datetime
from collections import defaultdict
import ipaddress
import shelve
from functools import wraps
import base64

try:
    import click
    import whois
    import pandas as pd
    import msticpy as mp
    import requests
    from redis import StrictRedis
    import msticpy.context.domain_utils as domain_utils
    from msticpy.transform import IoCExtract, base64unpack
    from msticpy.context.geoip import GeoLiteLookup, IPStackLookup
except Exception as err:
    print("pip3 install msticpy pandas whois redis requests click")

try:
    import sigma_cli_rules
except:
    print("You need this file to execute sigmas rules!")
    print("https://github.com/rezen/sigma-stuff/blob/main/sigma_cli_rules.py")


DATA_TOR_EXIT_NODES = None
DATA_FRESH_DOMAINS = {}

THRESHOLD_DOMAIN_AGE = int(os.environ.get("THRESHOLD_DOMAIN_AGE", 60))

ERROR_COUNT_WHOIS = 0

CONFIG_SKETCHY_DOMAINS = set()
CONFIG_SKETCHY_IPS = set()

CONFIG_MASKS = {
    # Windows defender has key embedded into script
    (
        r'(OnboardingInfo \/t REG_SZ \/f \/d )([^\s]+)', r'\1xxxxx'
    ),
    (
        r'net\s+localgroup\s+([^\s]+)\s+(\\?"[^"]+\"|[^\s]+)\s+(\/[a-z0-9]+)', r'net localgroup xxx xxx \3',
    ),
    (
        r'\\Users\\[^\s]+\\', r'\\Users\\xxxxx\\'
    )
}
CONFIG_MASKS_ID = hashlib.md5('_'.join(r[0] for r in CONFIG_MASKS).encode("utf8")).hexdigest()

COMMAND_TAGGER_VERSION = None

IOC_FACTS = defaultdict(dict)


_redis_client = None


def get_redis_client():
    global _redis_client
    if not _redis_client:
        _redis_client = StrictRedis()
    return _redis_client


class JsonxEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def json_dumps(obj):
    return json.dumps(obj, cls=JsonxEncoder)


def shelve_it(file_name):
    d = shelve.open(file_name)

    def decorator(func):
        def new_func(param):
            if param not in d:
                d[param] = func(param)
            return d[param]

        return new_func

    return decorator

def get_quoted_strings(content):
    single_quotes = re.findall(r"'([^']+)'", content)
    dbl_quotes = re.findall(r'"([^"]+)"', content)
    return single_quotes + dbl_quotes

def find_base64_encoded_parts(content, threshold=20):
    if len(content) < threshold:
        return []

    findings = []
    quoted = get_quoted_strings(content)
    parts = list(set(content.split() + quoted))
    for part in parts:
        if len(part) < threshold:
            continue
        try:
            decoded = base64.b64decode(part).decode("utf8")
            decoded = decoded.replace('\x00','').encode("ascii", "ignore").decode().strip()
            if len(decoded) < threshold:
                continue

            findings.append((part, decoded, 'base64'))
        except Exception as err:
            pass
    return findings


def command_line_masked(command_line):
    global CONFIG_MASKS
    masked = str(command_line)

    meta ={}
    for pattern, replacement in CONFIG_MASKS:
        masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
    return masked, meta


def command_line_tags(command_line):
    tags = {}
    if 'user32' in command_line and 'LockWorkStation' in command_line:
        tags['win_lock_workstation'] = True

    if '.s3.' in command_line and 'amazonaws.com' in command_line:
        tags['aws_s3'] = True

    if ' reg ' in command_line:
        tags['registry_tweaks'] = []
        for entry in re.finditer(r'reg\s+(?P<action>[a-z]+)\s+(?P<resource>\\?"[^"]+\"|[^\s]+)', command_line):
            tags['registry_tweaks'].append(entry.groupdict())
    return tags



def cached(func):
    """
    Decorator that caches the results of the function call.

    We use Redis in this example, but any cache (e.g. memcached) will work.
    We also assume that the result of the function can be seralized as JSON,
    which obviously will be untrue in many situations. Tweak as needed.
    """
    client = get_redis_client()

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Generate the cache key from the function's arguments.
        # If your method body changes, you will want to clear the cache
        # redis-cli --scan --pattern get_sigmas_matches-* | xargs redis-cli del
        key_parts = [func.__name__] + [
            hashlib.md5("_".join(list(args)).encode("utf8")).hexdigest()
        ]
        key = "-".join(key_parts)
        result = client.get(key)

        if result is None:
            # Run the function and cache the result for next time.
            value = func(*args, **kwargs)
            value_json = json_dumps(value)
            client.set(key, value_json)
        else:
            # Skip the function entirely and use the cached value instead.
            value_json = result.decode("utf-8")
            value = json.loads(value_json)

        return value

    if not client:
        return shelve_it("data/shelve__" + func.__name__)
    return wrapper


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


@cached
def get_sigmas_matches(command: str):
    matches = []
    for method in sigma_cli_rules.CLI_ONLY_COMPAT_METHODS:
        try:
            sigma_rule = getattr(sigma_cli_rules, method)
            is_match = sigma_rule(
                {
                    "_raw": Stringy(command),
                    "COMMAND_LINE": Stringy(command),
                }
            )
            if is_match:
                # Include level in the string for starters
                method = method + ":" + sigma_rule.sigma_meta.get("level", "_")
                matches.append(method[6:])
        except Exception as err:
            pass
    return matches


@cached
def ip_is_valid_and_public(ip_string):
    try:
        ip_data = ipaddress.ip_address(ip_string)
        return ip_data.is_private != True
    except ValueError:
        return False


@cached
def get_domain_age_in_days(domain: str):
    global ERROR_COUNT_WHOIS
    parts = domain_utils.dns_components(domain)
    target = parts["domain"] + "." + parts["suffix"]
    try:
        record = whois.whois(target)
    except Exception as err:
        ERROR_COUNT_WHOIS += 1
        return None
    if not record.creation_date:
        return None
    created_at = record.creation_date
    if isinstance(created_at, list):
        created_at = created_at.pop(0)

    try:
        delta = datetime.now() - created_at
    except:
        print("Issue with domain")
        print(domain)
        print(record)
        exit()
    return delta.days


@cached
def get_ip_country(ip: str):
    ip_location = GeoLiteLookup()
    loc_result, ip_entity = ip_location.lookup_ip(ip_address=ip)
    return loc_result.pop().get("country", {}).get("iso_code")


@cached
def is_tor_exit_node(ip: str):
    global DATA_TOR_EXIT_NODES
    if DATA_TOR_EXIT_NODES is None:
        response = requests.get(
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"
        )
        DATA_TOR_EXIT_NODES = set(response.body.split("\n"))
    return ip in DATA_TOR_EXIT_NODES


@cached
def get_msticpy_iocs(command: str):
    extractor = get_ioc_extractor()
    return extractor.extract(command)


def iocs_to_list(iocs, include={}):
    records = []
    for ioc_type in iocs:
        for entry in iocs[ioc_type]:
            records.append(
                {
                    **{
                        "ioc_type": ioc_type,
                        "ioc_value": entry,
                    },
                    **include,
                }
            )
    return records


def command_line_meta(command: str):
    global CONFIG_MASKS_ID, COMMAND_TAGGER_VERSION

    if COMMAND_TAGGER_VERSION is None:
        import inspect
        src_code = str(inspect.getsource(command_line_tags))
        COMMAND_TAGGER_VERSION = hashlib.md5(src_code.encode("utf8")).hexdigest()

    return {
        'tagger_id': COMMAND_TAGGER_VERSION,
        'mask_id': CONFIG_MASKS_ID,
        'concat_ratio':  round(command.count("+") / len(command), 3),
    }

def command_to_ioc_data(command: str, parent_cid=None):
    # Cleanup invalid json bits in command
    cid = "" + hashlib.md5(command.encode("utf8")).hexdigest()
    iocs = get_msticpy_iocs(command)
    masked_command, mask_meta = command_line_masked(command)

    children = []
    child_iocs = []

    command_meta = command_line_meta(command)
    command_meta['children_count'] = 0
    parts = find_base64_encoded_parts(command)
    for _, decoded, _ in parts:
        if not decoded:
            continue
        subs, sub_iocs = command_to_ioc_data(decoded, cid)
        children.extend(subs)
        child_iocs.extend(sub_iocs)

        command_meta['children_count'] += len(subs)

    record = {
        "cid": cid,
        'parent_cid': parent_cid,
        "image": _parse_image(command),
        "command_line": command,
        'masked': masked_command,
        'masked_cid': hashlib.md5(masked_command.encode("utf8")).hexdigest(),
        "sigma_matches": get_sigmas_matches(command),
        "iocs_count": 0,
        "iocs_ipv4": list(iocs.get("ipv4", set())),
        "iocs_dns": list(iocs.get("dns", set())),
        "iocs_ipv4_countries": set(),
        "iocs_domains_fresh": False,
        'meta': command_meta,
        'tags': command_line_tags(command),
        # @todo get urls
    }
    sigma_count = len(record["sigma_matches"])
    sigmas_severe_count = len(
        [r for r in record["sigma_matches"] if ":high" in r or ":crit" in r]
    )


    record["sigma_matches_count"] = sigma_count
    record["sigma_severe_count"] = sigmas_severe_count

    ti_lookup = mp.TILookup()
    # print(ti_lookup.provider_status)

    # Check if domain is newer, that raises suspicion
    if record["iocs_dns"]:
        for dns in record["iocs_dns"]:
            age = get_domain_age_in_days(dns)
            if sigma_count:
                IOC_FACTS[dns]["has_sigmas_matches"] = True

            if sigmas_severe_count:
                IOC_FACTS[dns]["has_sigmas_severe_matches"] = True

            if age:
                IOC_FACTS[dns]["age"] = age

            if age != None and age < THRESHOLD_DOMAIN_AGE:
                DATA_FRESH_DOMAINS[dns] = age
                record["iocs_domains_fresh"] = age
                break

    # If country of ip is different than ip of initiator, likely suspicious
    for ip in record["iocs_ipv4"]:
        if not ip_is_valid_and_public(ip):
            continue

        country = get_ip_country(ip)
        if sigma_count:
            IOC_FACTS[ip]["has_sigmas_matches"] = True

        if sigmas_severe_count:
            IOC_FACTS[ip]["has_sigmas_severe_matches"] = True

        if not country:
            continue

        IOC_FACTS[ip]["country"] = country
        record["iocs_ipv4_countries"].add(country)

    record["iocs_ipv4_countries"] = list(record["iocs_ipv4_countries"])
    record["iocs_network_count"] = len(record["iocs_ipv4"]) + len(record["iocs_dns"])
    record["sigma_matches_count"] = len(record["sigma_matches"])
    return [record] + children, iocs_to_list(iocs, {"cid": cid}) + child_iocs


target_csv = sys.argv[1]
if not os.path.exists(target_csv):
    print(f"!! You have to provided a target csv to consume - file={target_csv}")
    exit(1)


command_column = os.environ.get("COMMAND_COL", "COMMAND_LINE")
print(f" - Reading file={target_csv} col={command_column} to as columns for commands")

df_source = pd.read_csv(target_csv)
df_source["CommandLine"] = df_source[command_column].apply(_parse_cmd)
df_source["cid"] = df_source["CommandLine"].apply(
    lambda x: hashlib.md5(x.encode("utf8")).hexdigest()
)


ioc_records = []

# Dedupe commands before processing them all
commands_list = list(set(df_source["CommandLine"].tolist()))


fh_iocs = open("data/iocs.csv", "w+")
iocs_writer = csv.DictWriter(fh_iocs, ['cid', 'ioc_type', 'ioc_value'])
iocs_writer.writeheader()


fh_sigma_matches = open("data/sigma_matches.csv", "w+")
fh_sigma_matches.write("cid,rule,level\n")

with click.progressbar(commands_list) as entries:
    with open("data/commands_parsed.json", "w+") as fh:
        for command in entries:
            if not command:
                continue

            # @todo denote longer to process records
            records, iocs = command_to_ioc_data(command)
            # Dump ioc records

            for ioc in iocs:
                iocs_writer.writerow(ioc)

            for record in records:
                cid = record["cid"]

                # Dump robust records
                fh.write(json_dumps(record) + "\n")


                # Dump sigma records
                for sigma_match in record["sigma_matches"]:
                    rule, level = sigma_match.split(":")
                    fh_sigma_matches.write(",".join([cid, rule, level]) + "\n")


    fh_iocs.close()
    fh_sigma_matches.close()


with open("data/ioc_facts.csv", "w+") as fh:
    fh.write(",".join(["ioc", "key", "value"]) + "\n")
    for key in IOC_FACTS:
        for fact_key in IOC_FACTS[key]:
            fh.write(",".join([key, fact_key, str(IOC_FACTS[key][fact_key])]) + "\n")
