# sigma-stuff

## Feeds
- https://github.com/hslatman/awesome-threat-intelligence


## Models


dns
name(id), a_record, tld, tags


whois
domain(id), tld, tags

url
url(id), protocol, hostname, path, tags

ip
address(unique), asn, city, country, tags



ioc_findings
cid,entity,entity_id,context=null,false_positive
xxx,url,34,powershell


sigma_rules
file_id, title, description, fields, level, hash, false_positives=[]

sigmas_rule_matches
cid, rule, created_at, false_positive

suspicious_entity
cid,target,target_type

suspicious_pattern
cid,regex,contains,not


evaluated_items (all possible sigma fields)
cid, image, command_line, had_sudo, had_base64, status, list, is_comprimised,tags


extractors (to figure out more)
when,pattern,name

filters


evaluated_edges
cid,target,target_type
x,blarg.com,dns
x,blarg.com,dns
x,1.1.23.3,ip



private networks
brew
chocolatey