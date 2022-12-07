#!/usr/bin/env python3
import re
import os
import ast
import yaml
from pathlib import Path
import json
from glob import glob
from sigma.configuration import SigmaConfiguration
from sigma.backends.streamalert import StreamAlertQueryBackend
from sigma.backends.sql import SQLBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from collections import defaultdict

RULE_TMPL = '''
def {function_name}(record):
    """
    file_id: {file_id}
    title: {title}
    fields: {fields_used}
    level: {level}
    description: {description}
    logsource: {logsource}
    """
    return {query}

{function_name}.sigma_meta = dict(
    level="{level}"
)
'''


class PythonX(StreamAlertQueryBackend):
    def generate(self, sigmaparser: SigmaParser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""

        self.excluded_fields = [
            item.lower() for item in sigmaparser.config.config.get("excludedfields", [])
        ]
        try:
            service = sigmaparser.parsedyaml["logsource"].get("service", "{service}")
            logsource = " - ".join(
                "{}:{}".format(k, v)
                for k, v in sigmaparser.parsedyaml["logsource"].items()
            )
            self.is_upper = "upper" in sigmaparser.config.config.get("tags", [])

        except KeyError:
            logsource = "{logsource}"
            service = "{service}"

        results = ""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)

            if query is None:
                continue
            results += RULE_TMPL.format(
                logsource=logsource,
                service=service,
                query=query,
                level=sigmaparser.parsedyaml.get("level", "low"),
                title=sigmaparser.parsedyaml["title"],
                function_name=sigmaparser.parsedyaml["function_name"],
                description=sigmaparser.parsedyaml.get("description", "-"),
                fields_used=sigmaparser.parsedyaml.get("fields", []),
                file_id=sigmaparser.parsedyaml.get("file_id", "-"),
            )
        return results


def fields_used(rule_config):
    def _field_raw(x):
        return x.split("|").pop(0)
    detection = rule_config.get("detection", {})
    all_fields = set()
    for key in detection:
        if isinstance(detection[key], dict):
            fields = [_field_raw(x) for x in list(detection[key].keys())]
            all_fields.update(fields)
        elif isinstance(detection[key], list):
            for entry in detection[key]:
                if isinstance(entry, dict):
                    fields = [_field_raw(x) for x in list(entry.keys())]
                    all_fields.update(fields)
    return sorted(list(all_fields))


sigma_dir = os.environ.get("SIGMA_DIR", str(Path.home()) + "/co/sigma")

if not os.path.exists(sigma_dir):
    print("! Sigma directory not cloned")
    print("mkdir -p ~/co")
    print("cd ~/co && git clone https://github.com/SigmaHQ/sigma.git")
    print()
    exit(1)

config = SigmaConfiguration(open(f"{sigma_dir}/tools/config/streamalert.yml"))
backend = PythonX(config)
sql_backend = SQLBackend(SigmaConfiguration(), "x")

files = glob(f"{sigma_dir}/rules/windows/process_creation/*.yml")
files.extend(glob(f"rules/custom/*.yml"))
skipped = 0
used = 0
error_count = 0

errored_code = "import re\n"
code = "import re\n"
by_fields = defaultdict(list)
compat_fields = set(["CommandLine"])
compat_methods = []
sql_code = ""

for file in files:
    codegen = ""
    rule_config = yaml.safe_load(open(file))
    rule_config["file_id"] = file.replace(sigma_dir, "").lstrip("/")
    rule_config["fields"] = fields_used(rule_config)
    title = rule_config["title"]
    title_temp = re.sub("\W *", " ", title).replace("  ", " ")
    rule_config["function_name"] = "sigma_" + "_".join(
        a.lower() for a in title_temp.split(" ")
    )
    fields = set(rule_config["fields"])
    is_cli_only = len(fields) == 1 and 'CommandLine' in fields

    try:
        parser = SigmaParser(rule_config, config)
    except:
        if is_cli_only:
            print("!!! Review " + rule_config["file_id"])
        continue



        # See if is command line only rule
    if is_cli_only:
        try:
            # @todo validate sql
            tmp_code =  sql_backend.generate(parser)
            if tmp_code:
                sql_code += f"-- sigma rule file {rule_config['file_id']};\n"
                sql_code += tmp_code
                sql_code += "\n\n"
        except: pass

    try:
        codegen = backend.generate(parser)
        ast.parse("import re\n" + codegen)
        code += codegen

        # See if is command line only rule
        if is_cli_only:
            compat_methods.append(rule_config["function_name"])

    except Exception as err:
        error_count += 1
        if is_cli_only:
            print("!!! Review " + rule_config["file_id"])
            errored_code += codegen

code += "\n"
code += "CLI_ONLY_COMPAT_METHODS=" + json.dumps(list(compat_methods), indent=2)
ast.parse(code)


with open("sigma_windows_proc_rules.py", "w+") as fh:
    fh.write(code)

with open("__failed_sigma_code.py", "w+") as fh:
    fh.write(errored_code)


with open("sigma_windows_proc_rules.sql", "w+") as fh:
    fh.write(sql_code)
