# https://towardsdatascience.com/visualizing-networks-in-python-d70f4cbeb259
import re
import os.path
import json
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import DeclarativeMeta
from functools import cache
from sqlalchemy.sql import text
import sqlalchemy
import logging
from sqlalchemy.sql.expression import cast
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
import pylev
from Levenshtein import distance as lev
from sqlalchemy.orm import aliased, relationship, lazyload, joinedload, backref
import base64


logging.basicConfig()
logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)


DATA_DIR = os.path.dirname(__file__) + "/data/"

DATA_COUNTRY_COORDS = {}
with open(DATA_DIR + "/country_coords.json", "r") as fh:
    DATA_COUNTRY_COORDS = json.load(fh)


def get_quoted_strings(content):
    single_quotes = re.findall(r"'([^']+)'", content)
    dbl_quotes = re.findall(r'"([^"]+)"', content)
    return single_quotes + dbl_quotes

def get_or_create(session, model, **kwargs):
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        session.add(instance)
        session.commit()
        return instance

tags = [
    'recon',
]
status = [
    "needs_review",
]
filters = {
    "net query%": "x",
    "net user%": "x",
    "netuser%": "x",
    "wmic netuser%": "x"
}

# create the extension
db = SQLAlchemy()
# create the app
app = Flask(__name__)
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATA_DIR + "/dataset.db"
# initialize the app with the extension
db.init_app(app)



def find_base64_encoded_parts(content):
    findings = []
    parts = content.split()
    for part in parts:
        try:
            decoded = base64.b64decode(part).decode("utf8")
            findings.append((part, decoded, 'base64'))
        except:
            pass
    return findings



def _sqlite_levenshtein(y, x):
    return pylev.levenshtein(str(y), str(x))

with app.app_context():
    @db.event.listens_for(db.engine, "first_connect")
    def connect(sqlite, connection_rec):
        # sqlite.enable_load_extension(True)
        # sqlite.execute("SELECT load_extension('C:\\spatialite32\\mod_spatialite')")
        # sqlite.enable_load_extension(False)
        print("first_connect")

    @db.event.listens_for(db.engine, "connect")
    def connect(sqlite, connection_rec):
        print("connect")
        print(sqlite)
        sqlite.create_function('PYLEVENSHTEIN', 2, _sqlite_levenshtein)


class AlchemyEncoder(json.JSONEncoder):
    def default(self, obj):
        print(obj.__class__)

        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [
                x for x in dir(obj) if not x.startswith("_") and x != "metadata"
            ]:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(
                        data
                    )  # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields
        return json.JSONEncoder.default(self, obj)


class DefaultModel:
    def to_dict(self):
        return self.__dict__

    @classmethod
    def by_cid(self, session, cid):
        return (
            session.query(self)
            .filter(self.cid == cid)
            .all()
        )


class Source(DefaultModel, db.Model):
    __tablename__ = "source"
    index = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.String)

    @classmethod
    def by_cid(self, session, cid):
        return (
            session.query(self)
            .filter(self.cid == cid)
            .all()
        )

class Ioc(DefaultModel, db.Model):
    __tablename__ = "iocs"
    index = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.String)
    ioc_type = db.Column(db.String)
    ioc_value = db.Column(db.String)


    @classmethod
    def with_country(self, session):
        return (
            session.query(self, IocFact.value.label("country"))
            .join(IocFact, IocFact.ioc == self.ioc_value)
            .filter(Ioc.ioc_type == "ipv4")
            .filter(IocFact.key == "country")
        )

    @classmethod
    def with_details(self, q):
        return q.join(CommandParsed, CommandParsed.cid == self.cid)

    @classmethod
    def by_dns(self, session, dns):
        return (
            session.query(self, CommandParsed)
            .join(CommandParsed, self.cid == CommandParsed.cid)
            .filter(self.ioc_type == "dns")
            .filter(self.ioc_value == dns)
        )

    @classmethod
    def by_ip(self, session, ip):
        return (
            session.query(self)
            .filter(self.ioc_type == "ip")
            .filter(self.ioc_value == ip)
        )

class IocFact(DefaultModel, db.Model):
    __tablename__ = "ioc_facts"
    index = db.Column(db.Integer, primary_key=True)
    ioc = db.Column(db.String)
    key = db.Column(db.String)
    value = db.Column(db.String)

    @classmethod
    def get_unique_countries(self, session):
        return [
            r.value
            for r in (
                session.query(self).distinct(self.value).filter(self.key == "country")
            )
        ]

    @classmethod
    def by_cid(self, session, cid):
        return (
            session.query(
                self,
            )
            .join(Ioc, (Ioc.cid == cid) & (self.ioc == Ioc.ioc_value))
            .all()
        )


class SigmaMatch(DefaultModel, db.Model):
    __tablename__ = "sigma_matches"
    index = db.Column(db.Integer, primary_key=True)

    cid = db.Column(db.String)
    rule = db.Column(db.String)
    level = db.Column(db.String)

    @classmethod
    def get_aggr_count(self, session, attr):
        column = getattr(self, attr)
        result = (
            session.query(column, sqlalchemy.func.count(self.cid).label("count"))
            .group_by(column)
            .all()
        )
        return {getattr(x, attr): x.count for x in result}


    @classmethod
    def by_cid(self, session, cid):
        return (
            session.query(self)
            .filter(self.cid == cid)
            .all()
        )

    @classmethod
    def by_country(self, session, country):
        return (
            session.query(self)
            .join(Ioc, Ioc.cid == self.cid)
            .join(IocFact, IocFact.ioc == Ioc.ioc_value)
            .filter(Ioc.ioc_type == "ipv4")
            .filter(IocFact.key == "country")
            .filter(IocFact.value == country)
            .all()
        )


class CommandStatus(DefaultModel, db.Model):
    __tablename__ = "command_status"


    cid = db.Column(db.String,  db.ForeignKey('commands_parsed.cid'), primary_key=True)
    status = db.Column(db.String)

    is_comprimised = db.Column(db.Boolean)
    is_false_positive = db.Column(db.Boolean)
    command_parsed = relationship("CommandParsed", back_populates="status", uselist=False)


class CommandParsed(DefaultModel, db.Model):
    __tablename__ = "commands_parsed"

    cid = db.Column(db.String(32))
    parent_cid = db.Column(db.String(32), db.ForeignKey('commands_parsed.cid'), nullable=True)

    status = relationship("CommandStatus", uselist=False, lazy="joined")
    sub_commands = relationship("CommandParsed", lazy="joined")

    index = db.Column(db.Integer, primary_key=True)


    image = db.Column(db.String)
    command_line = db.Column(db.String)
    # tags = db.Column(db.JSON)

    iocs_domains_fresh = db.Column(db.Boolean)
    iocs_network_count = db.Column(db.Integer)
    iocs_count = db.Column(db.Integer)
    iocs_ipv4 = db.Column(db.JSON)
    iocs_dns = db.Column(db.JSON)
    iocs_ipv4_countries = db.Column(db.String)

    sigma_severe_count = db.Column(db.Integer)
    sigma_matches_count = db.Column(db.Integer)
    sigma_matches = db.Column(db.JSON)

    meta = db.Column(db.JSON)
    tags = db.Column(db.JSON)

    is_comprimised = db.Column(db.Boolean)

    @hybrid_property
    def is_comprimised_status(self):
        return self.status.is_comprimised

    @classmethod
    def by_high_concat_ratio(self, session, threshold=0.03):
        return (
            session.query(self)
            .filter(
                cast(sqlalchemy.func.json_extract(self.meta, '$.concat_ratio'), sqlalchemy.Float) > threshold
            )
        )


    @classmethod
    def by_sigma_rules(self, session, rules):
        return (
            session.query(
                self,
            )
            .join(SigmaMatch, SigmaMatch.cid == self.cid)
            .filter(SigmaMatch.rule.in_(rules))
        )

    @classmethod
    def get_similar_to_cid(self, session, cid):
        record = session.query(self.command_line).filter(self.cid==cid).one()
        length = len(record.command_line)

        return (
            session.query(
                self
            )
            # .filter(sqlalchemy.func.length(self.command_line) >= length - 10)
            # .filter(sqlalchemy.func.length(self.command_line) <= length + 10)
            .filter(sqlalchemy.func.length(self.command_line) <= 200) # Only look at smaller strings
            .filter(sqlalchemy.func.PYLEVENSHTEIN(self.command_line, record.command_line) < 25)
            .order_by(sqlalchemy.func.PYLEVENSHTEIN(self.command_line, record.command_line).desc())
        )


    @classmethod
    def by_ioc(self, session, ioc_value):
        return (
            session.query(
                self,
            )
            .join(Ioc, Ioc.cid == self.cid)
            .filter(Ioc.ioc_value == ioc_value)
        )

    @classmethod
    def by_ioc_fact(self, session, fact_key, fact_value=None):
        q = (
            session.query(self)
            .join(Ioc, Ioc.cid == self.cid)
            .join(IocFact, IocFact.ioc == Ioc.ioc_value)
        )
        if fact_key:
            if isinstance(fact_key, str):
                q = q.filter(IocFact.key == fact_key)
            elif callable(fact_key):
                q = fact_key(q)
        if fact_value:
            q = q.filter(IocFact.value == fact_value)
        return q

    @classmethod
    def by_country(self, session, country):
        return (
            session.query(self)
            .join(Ioc, Ioc.cid == self.cid)
            .join(IocFact, IocFact.ioc == Ioc.ioc_value)
            .filter(Ioc.ioc_type == "ipv4")
            .filter(IocFact.key == "country")
            .filter(IocFact.value == country)
            .all()
        )

def geo_features_for_countries(countries):
    features = []
    with open(DATA_DIR + "countries.geo.json") as fh:
        for line in fh.readlines():
            line = line.strip()
            if line.endswith(","):
                line = line[0:-1]
            try:
                data = json.loads(line.rstrip(","))
                if data["id"] == "CHN":
                    data["id"] = "CN"
                country_id = data["id"][0:2]
                if country_id in countries:
                    features.append(data)
            except Exception as err:
                print(err)
    return {"type": "FeatureCollection", "features": features}


def row2dict(row, parent=None):
    d = {}
    attr_keys = [a for  a in dir(row) if not a.startswith('_')]


    for key in attr_keys:

        try:
            val = getattr(row, key)
        except:
            val =None

        if val == parent:
            continue

        if isinstance(val, DefaultModel):
            d[key] = row2dict(val, row)

    for column in row.__table__.columns:

        d[column.name] = getattr(row, column.name)
    return d


def json_data_response(data):
    return jsonify(dict(data=data))

@app.route("/_api/sigma/counts_by_rule")
def api_sigmas_counts_by_rule():
    return jsonify(SigmaMatch.get_aggr_count(db.session, "rule"))

@app.route("/_api/sigma/counts_by_level")
def api_sigmas_counts_by_level():
    return jsonify(SigmaMatch.get_aggr_count(db.session, "level"))


@app.route("/_api/sigma/by_country/<country>")
def api_sigmas_by_country(country):
    results = SigmaMatch.by_country(db.session, country.upper())
    return jsonify([row2dict(s) for s in results])



@app.route("/_api/suspicious")
def api_suspicious():
    print("-------------------------")
    print("=============================")
    results = db.session.query(CommandParsed).join(CommandStatus,  CommandStatus.cid == CommandParsed.cid).options(
        joinedload(CommandParsed.status),
        joinedload(CommandParsed.sub_commands),
    ).filter(CommandStatus.is_comprimised == None).all()
    return json_data_response([row2dict(s) for s in results])



@app.route("/_api/suspicious/by_sigma/<rule>")
def api_suspicious_by_sigmas(rule):
    suspicious = CommandParsed.by_sigma_rules(db.session, [rule])
    return json_data_response([row2dict(s) for s in suspicious])




@app.route("/_api/suspicious/by_ioc")
def api_suspicious_by_ioc():
    suspicious = CommandParsed.by_ioc(db.session, "zoom.us")
    return json_data_response([row2dict(s) for s in suspicious])



@app.route("/_api/suspicious/by_ioc_fact")
def api_suspicious_by_ioc_fact():
    suspicious = CommandParsed.by_ioc_fact(db.session, "country", "CN")
    return json_data_response([row2dict(s) for s in suspicious])


@app.route("/_api/suspicious/by_domain_fresh")
def api_suspicious_domain_youngt():
    suspicious = CommandParsed.by_ioc_fact(
        db.session,
        lambda x: x.filter(IocFact.key == "age").filter(
            cast(IocFact.value, sqlalchemy.Integer) < 100
        ),
    )
    return json_data_response([row2dict(s) for s in suspicious])


@app.route("/_api/dns/<name>")
def api_get_dns_by_name(name):
    return jsonify({
       'name': name,
    })


@app.route("/_api/ioc_fact")
def api_domain_freshness():
    query = request.args
    comparison_value = None
    if query['value']:
        if query['value'].startswith('>') or query['value'].startswith('<'):
            print(query['value'])

    suspicious = db.session.query(IocFact).filter(IocFact.key == query['key']).filter(
        cast(IocFact.value, sqlalchemy.Integer) < 100
    )
    return json_data_response([row2dict(s) for s in suspicious])



@app.route("/view/dns/<name>")
def view_get_dns(name):
    iocs = Ioc.by_dns(db.session, name).all()
    return render_template("dns.html", **{
        'iocs': [r for r in iocs],
    })



@app.route("/_api/ip/<ip>")
def api_get_ip(ip):
    return jsonify({
       'ip': ip,
    })

@app.route("/view/ip/<ip>")
def view_get_ip(ip):
    iocs = Ioc.by_ip(db.session, ip).all()
    return render_template("ip.html", **{
        'iocs': iocs,
    })

@app.route("/_api/bulk/is_comprimised", methods=['POST'])
def api_is_comprimised():
    payload = request.get_json()
    cids =  payload.get('cids', [])
    stmt = sqlalchemy.update(CommandStatus).where(CommandStatus.cid.in_(cids)).values(is_comprimised=payload.get('is_comprimised'))
    db.session.execute(stmt)
    db.session.commit()
    return jsonify(dict(payload))

@app.route("/_api/cid/<cid>")
def api_get_cid(cid):
    record = db.session.query(CommandParsed).filter(CommandParsed.cid == cid).one_or_none()
    record = row2dict(record)
    facts = IocFact.by_cid(db.session, cid)
    facts = [row2dict(f) for f in facts]
    return jsonify({
        'data': record,
        'ioc_facts': facts,
        'sigma_matches': [row2dict(r) for r in  SigmaMatch.by_cid(db.session, cid)],
    })

@app.route("/_api/cid/<cid>/is_comprimised", methods=['POST'])
def api_post_is_comprimised(cid):
    payload = request.get_json()
    cids =  [cid]
    stmt = sqlalchemy.update(CommandStatus).where(CommandStatus.cid.in_(cids)).values(is_comprimised=payload.get('is_comprimised'))
    db.session.execute(stmt)
    db.session.commit()
    return jsonify(dict(payload))


@app.route("/_api/cid/<cid>/sources")
def api_get_cid_sources(cid):
    result = db.session.execute("SELECT * FROM source WHERE cid = :cid", params={'cid': cid})
    return jsonify([dict(r) for r in result])




def additional_filters():
    return {
        'powershell_base64': db.session.query(CommandParsed).filter((CommandParsed.command_line.like('%-enc %')) | (CommandParsed.command_line.like('%-encodedCommand %')))
    }



@app.route("/view/cid/<cid>")
def view_get_cid(cid):
    record = db.session.query(CommandParsed).filter(CommandParsed.cid == cid).first()
    sources = []
    iocs = []
    facts = []
    encoded_parts = []
    status = {}
    sources = []
    sub_commands = []
    if record:
        quoted = get_quoted_strings(record.command_line)
        encoded_parts = find_base64_encoded_parts(record.command_line)
        status = record.status
        sub_commands = [row2dict(r) for r in record.sub_commands]
        record = row2dict(record)
        result = db.session.execute("SELECT * FROM source WHERE cid = :cid", params={'cid': cid})
        sources = [dict(r) for r in result]

        facts = IocFact.by_cid(db.session, cid)
        facts = [row2dict(f) for f in facts]
        sources = [row2dict(f) for f in Source.by_cid(db.session, cid)]
        iocs = [row2dict(f) for f in Ioc.by_cid(db.session, cid)]

    else:
        record = {
            'command_line': ''
        }

    return render_template("cid.html", **{
        'status': status,
        'suspect': record,
        'sources': sources,
        'encoded_parts': encoded_parts,
        'ioc_facts': facts,
        'iocs': iocs,
        'sigma_matches': [row2dict(r) for r in  SigmaMatch.by_cid(db.session, cid)],
        'sources': sources,
        'sub_commands': sub_commands,
    })


@app.route("/_api/cid/<cid>/similar")
def api_get_cid_similar(cid):
    # @todo background job
    # @todo don't get similar for long strings
    results = CommandParsed.get_similar_to_cid(db.session, cid).all()
    return jsonify([row2dict(f) for f in results])


@app.route("/_api/cid/<cid>/facts")
def api_get_cid_facts(cid):
    facts = IocFact.by_cid(db.session, cid)
    return jsonify([row2dict(f) for f in facts])


@app.route("/_api/geo/features")
def api_geo_features():
    countries = IocFact.get_unique_countries(db.session)
    features = geo_features_for_countries(set(countries))
    return jsonify(features)


@app.route("/_api/geo/countries")
def api_countries():
    results = Ioc.with_country(db.session)
    return jsonify(
        [
            dict(
                **row2dict(r.Ioc),
                coords=DATA_COUNTRY_COORDS.get(r.country),
                country=r.country
            )
            for r in results
        ],
    )


@app.route("/")
def index():

    sigma_rule_counts = SigmaMatch.get_aggr_count(db.session, "rule")

    return render_template("index.html", **{
        'sigma_rule_counts': sigma_rule_counts,
    })
