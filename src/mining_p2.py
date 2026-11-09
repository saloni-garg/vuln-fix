"""Phase 2 mining (SPEC Section 4 source stage, extended to all 8 CWE
families of Section 6).

Same discipline as Phase 1 mining.py: query OSV (which mirrors GHSA)
per package, group ALL entries (GHSA + PYSEC) per CVE before filtering
(the Phase 1 D1 lesson), keep CVEs carrying any of the 8 target CWEs,
resolve fix commits from OSV GIT ranges / FIX references where present.
Nothing here is trusted as ground truth; the funnel verifies.

Output: build/phase2/candidates_p2.jsonl (Phase 1 files are evidence
and are not overwritten).
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from . import snapshots

ROOT = snapshots.ROOT
OUT = ROOT / "build" / "phase2"
TARGET_CWES = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502",
               "CWE-611", "CWE-918", "CWE-94"}

# pypi name -> (repo url, local clone dir name, licence best-effort)
PACKAGES = {
    "django": ("https://github.com/django/django.git", "django-5.2", "BSD-3-Clause"),
    "flask": ("https://github.com/pallets/flask.git", "flask", "BSD-3-Clause"),
    "werkzeug": ("https://github.com/pallets/werkzeug.git", "werkzeug", "BSD-3-Clause"),
    "jinja2": ("https://github.com/pallets/jinja2.git", "jinja2", "BSD-3-Clause"),
    "markupsafe": ("https://github.com/pallets/markupsafe.git", "markupsafe", "BSD-3-Clause"),
    "tornado": ("https://github.com/tornadoweb/tornado.git", "tornado", "Apache-2.0"),
    "aiohttp": ("https://github.com/aio-libs/aiohttp.git", "aiohttp", "Apache-2.0"),
    "starlette": ("https://github.com/encode/starlette.git", "starlette", "BSD-3-Clause"),
    "fastapi": ("https://github.com/fastapi/fastapi.git", "fastapi", "MIT"),
    "bottle": ("https://github.com/bottlepy/bottle.git", "bottle", "MIT"),
    "cherrypy": ("https://github.com/cherrypy/cherrypy.git", "cherrypy", "BSD-3-Clause"),
    "twisted": ("https://github.com/twisted/twisted.git", "twisted", "MIT"),
    "scrapy": ("https://github.com/scrapy/scrapy.git", "scrapy", "BSD-3-Clause"),
    "sqlalchemy": ("https://github.com/sqlalchemy/sqlalchemy.git", "sqlalchemy", "MIT"),
    "piccolo": ("https://github.com/piccolo-orm/piccolo.git", "piccolo", "MIT"),
    "tortoise-orm": ("https://github.com/tortoise/tortoise-orm.git", "tortoise-orm", "MIT"),
    "peewee": ("https://github.com/coleifer/peewee.git", "peewee", "MIT"),
    "djangorestframework": ("https://github.com/encode/django-rest-framework.git", "drf", "BSD-3-Clause"),
    "wagtail": ("https://github.com/wagtail/wagtail.git", "wagtail", "BSD-3-Clause"),
    "gitpython": ("https://github.com/gitpython-developers/GitPython.git", "gitpython", "BSD-3-Clause"),
    "dulwich": ("https://github.com/dulwich/dulwich.git", "dulwich", "Apache-2.0"),
    "paramiko": ("https://github.com/paramiko/paramiko.git", "paramiko", "LGPL-2.1"),
    "pyyaml": ("https://github.com/yaml/pyyaml.git", "pyyaml", "MIT"),
    "celery": ("https://github.com/celery/celery.git", "celery", "BSD-3-Clause"),
    "kombu": ("https://github.com/celery/kombu.git", "kombu", "BSD-3-Clause"),
    "httplib2": ("https://github.com/httplib2/httplib2.git", "httplib2", "MIT"),
    "requests": ("https://github.com/psf/requests.git", "requests", "Apache-2.0"),
    "urllib3": ("https://github.com/urllib3/urllib3.git", "urllib3", "MIT"),
    "lxml": ("https://github.com/lxml/lxml.git", "lxml", "BSD-3-Clause"),
    "xmlschema": ("https://github.com/sissaschool/xmlschema.git", "xmlschema", "MIT"),
    "cairosvg": ("https://github.com/Kozea/CairoSVG.git", "cairosvg", "LGPL-3.0"),
    "reportlab": ("https://github.com/DistinguishedDeveloper/reportlab.git", "reportlab", "BSD-3-Clause"),
    "mako": ("https://github.com/sqlalchemy/mako.git", "mako", "MIT"),
    "genshi": ("https://github.com/edgewall/genshi.git", "genshi", "BSD-3-Clause"),
    "bleach": ("https://github.com/mozilla/bleach.git", "bleach", "Apache-2.0"),
    "mistune": ("https://github.com/lepture/mistune.git", "mistune", "BSD-3-Clause"),
    "markdown": ("https://github.com/Python-Markdown/markdown.git", "markdown", "BSD-3-Clause"),
    "pygments": ("https://github.com/pygments/pygments.git", "pygments", "BSD-2-Clause"),
    "setuptools": ("https://github.com/pypa/setuptools.git", "setuptools", "MIT"),
    "pip": ("https://github.com/pypa/pip.git", "pip", "MIT"),
    "wheel": ("https://github.com/pypa/wheel.git", "wheel", "MIT"),
    "chameleon": ("https://github.com/malthe/chameleon.git", "chameleon", "BSD-3-Clause"),
    "kajiki": ("https://github.com/nandoflorestan/kajiki.git", "kajiki", "MIT"),
    "httpie": ("https://github.com/httpie/cli.git", "httpie", "BSD-3-Clause"),
    "yt-dlp": ("https://github.com/yt-dlp/yt-dlp.git", "yt-dlp", "Unlicense"),
    "streamlink": ("https://github.com/streamlink/streamlink.git", "streamlink", "BSD-2-Clause"),
    "invoke": ("https://github.com/pyinvoke/invoke.git", "invoke", "BSD-2-Clause"),
    "fabric": ("https://github.com/fabric/fabric.git", "fabric", "BSD-2-Clause"),
    "jsonpickle": ("https://github.com/jsonpickle/jsonpickle.git", "jsonpickle", "BSD-3-Clause"),
    "dill": ("https://github.com/uqfoundation/dill.git", "dill", "BSD-3-Clause"),
    "ruamel.yaml": ("https://github.com/commx/ruamel-yaml.git", "ruamel-yaml", "MIT"),
    "asteval": ("https://github.com/lmfit/asteval.git", "asteval", "MIT"),
    "feedparser": ("https://github.com/kurtmckee/feedparser.git", "feedparser", "BSD-2-Clause"),
    "icalendar": ("https://github.com/collective/icalendar.git", "icalendar", "BSD-2-Clause"),
    "odfpy": ("https://github.com/eea/odfpy.git", "odfpy", "GPL-2.0"),
    "python-docx": ("https://github.com/python-openxml/python-docx.git", "python-docx", "MIT"),
    "openpyxl": ("https://github.com/theorchard/openpyxl.git", "openpyxl", "MIT"),
    "defusedxml": ("https://github.com/tiran/defusedxml.git", "defusedxml", "PSF-2.0"),
    "xmltodict": ("https://github.com/martinblech/xmltodict.git", "xmltodict", "MIT"),
    "sentry-sdk": ("https://github.com/getsentry/sentry-python.git", "sentry-sdk", "MIT"),
    "gradio": ("https://github.com/gradio-app/gradio.git", "gradio", "Apache-2.0"),
    "mlflow": ("https://github.com/mlflow/mlflow.git", "mlflow", "Apache-2.0"),
    "streamlit": ("https://github.com/streamlit/streamlit.git", "streamlit", "Apache-2.0"),
    "luigi": ("https://github.com/spotify/luigi.git", "luigi", "Apache-2.0"),
    "sympy": ("https://github.com/sympy/sympy.git", "sympy", "BSD-3-Clause"),
    "dateparser": ("https://github.com/scrapinghub/dateparser.git", "dateparser", "BSD-3-Clause"),
    "marshmallow": ("https://github.com/marshmallow-code/marshmallow.git", "marshmallow", "MIT"),
    "pydantic": ("https://github.com/pydantic/pydantic.git", "pydantic", "MIT"),
    "pillow": ("https://github.com/python-pillow/Pillow.git", "pillow", "HPND"),
    "cryptography": ("https://github.com/pyca/cryptography.git", "cryptography", "Apache-2.0"),
    "pyjwt": ("https://github.com/jpadilla/pyjwt.git", "pyjwt", "MIT"),
    "itsdangerous": ("https://github.com/pallets/itsdangerous.git", "itsdangerous", "BSD-3-Clause"),
    "safety": ("https://github.com/pyupio/safety.git", "safety", "MIT"),
    "rq": ("https://github.com/rq/rq.git", "rq", "BSD-2-Clause"),
    "huey": ("https://github.com/coleifer/huey.git", "huey", "MIT"),
    "nameko": ("https://github.com/nameko/nameko.git", "nameko", "Apache-2.0"),
    "glances": ("https://github.com/nicolargo/glances.git", "glances", "LGPL-3.0"),
    "superset": ("https://github.com/apache/superset.git", "superset", "Apache-2.0"),
    "airflow": ("https://github.com/apache/airflow.git", "airflow", "Apache-2.0"),
    "salt": ("https://github.com/saltstack/salt.git", "salt", "Apache-2.0"),
    "ansible": ("https://github.com/ansible/ansible.git", "ansible", "GPL-3.0"),
    "web2py": ("https://github.com/web2py/web2py.git", "web2py", "LGPL-3.0"),
    "reflex": ("https://github.com/reflex-dev/reflex.git", "reflex", "Apache-2.0"),
    "nicegui": ("https://github.com/zauberzeug/nicegui.git", "nicegui", "MIT"),
    "solara": ("https://github.com/widgetti/solara.git", "solara", "MIT"),
    "panel": ("https://github.com/holoviz/panel.git", "panel", "BSD-3-Clause"),
    "bokeh": ("https://github.com/bokeh/bokeh.git", "bokeh", "BSD-3-Clause"),
    "notebook": ("https://github.com/jupyter/notebook.git", "notebook", "BSD-3-Clause"),
    "jupyter-server": ("https://github.com/jupyter/jupyter_server.git", "jupyter-server", "BSD-3-Clause"),
    "aiofiles": ("https://github.com/Tinche/aiofiles.git", "aiofiles", "Apache-2.0"),
    "python-multipart": ("https://github.com/Kludex/python-multipart.git", "python-multipart", "Apache-2.0"),
    "django-allauth": ("https://github.com/pennersr/django-allauth.git", "django-allauth", "MIT"),
    "social-auth-app-django": ("https://github.com/python-social-auth/social-app-django.git", "social-app-django", "BSD-3-Clause"),
    "oauthlib": ("https://github.com/oauthlib/oauthlib.git", "oauthlib", "BSD-3-Clause"),
    "requests-oauthlib": ("https://github.com/requests/requests-oauthlib.git", "requests-oauthlib", "ISC"),
    "pyparsing": ("https://github.com/pyparsing/pyparsing.git", "pyparsing", "MIT"),
    "fonttools": ("https://github.com/fonttools/fonttools.git", "fonttools", "MIT"),
    "matplotlib": ("https://github.com/matplotlib/matplotlib.git", "matplotlib", "PSF-2.0"),
    "numpy": ("https://github.com/numpy/numpy.git", "numpy", "BSD-3-Clause"),
    "pandas": ("https://github.com/pandas-dev/pandas.git", "pandas", "BSD-3-Clause"),
    "keras": ("https://github.com/keras-team/keras.git", "keras", "Apache-2.0"),
    "transformers": ("https://github.com/huggingface/transformers.git", "transformers", "Apache-2.0"),
    "bentoml": ("https://github.com/bentoml/BentoML.git", "bentoml", "Apache-2.0"),
    "ray": ("https://github.com/ray-project/ray.git", "ray", "Apache-2.0"),
    "vllm": ("https://github.com/vllm-project/vllm.git", "vllm", "Apache-2.0"),
    "gradio-client": ("https://github.com/gradio-app/gradio.git", "gradio", "Apache-2.0"),
}


def osv_query(package: str) -> list[dict]:
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps({"package": {"name": package,
                                       "ecosystem": "PyPI"}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r).get("vulns", [])


def cve_of(vuln: dict) -> str | None:
    for a in vuln.get("aliases", []):
        if a.startswith("CVE-"):
            return a
    return vuln["id"] if vuln["id"].startswith("CVE-") else None


def fix_from_osv(vuln: dict) -> str | None:
    for a in vuln.get("affected", []):
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                for e in r.get("events", []):
                    if "fixed" in e and re.fullmatch(r"[0-9a-f]{40}",
                                                     e["fixed"]):
                        return e["fixed"]
    for ref in vuln.get("references", []):
        if ref.get("type") == "FIX":
            m = re.search(r"/commit/([0-9a-f]{40})", ref.get("url", ""))
            if m:
                return m.group(1)
    return None


def mine() -> tuple[list[dict], list[dict]]:
    candidates, errors = [], []
    for pkg, (url, local, licence) in sorted(PACKAGES.items()):
        try:
            vulns = osv_query(pkg)
        except Exception as e:
            errors.append({"package": pkg, "stage": "mining",
                           "outcome": "error", "reason": str(e)})
            continue
        grouped: dict[str, list[dict]] = {}
        for v in vulns:
            cve = cve_of(v)
            if cve is not None:
                grouped.setdefault(cve, []).append(v)
        for cve, entries in grouped.items():
            cwes = []
            for v in entries:
                for c in v.get("database_specific", {}).get("cwe_ids", []):
                    if c in TARGET_CWES and c not in cwes:
                        cwes.append(c)
            if not cwes:
                continue
            v = entries[0]
            fixed_versions = []
            fix_commit = None
            for entry in entries:
                sha = fix_from_osv(entry)
                if sha and fix_commit is None:
                    fix_commit = sha
                for a in entry.get("affected", []):
                    for r in a.get("ranges", []):
                        for e in r.get("events", []):
                            if "fixed" in e and r.get("type") == "ECOSYSTEM":
                                fixed_versions.append(e["fixed"])
            refs = [ref.get("url", "") for entry in entries
                    for ref in entry.get("references", [])][:20]
            candidates.append({
                "package": pkg, "cve": cve, "ghsa": v["id"],
                "cwes": cwes, "cwe": cwes[0],
                "summary": v.get("summary", ""),
                "published": v.get("published", "")[:10],
                "repo_url": url, "repo_local": local,
                "licence": licence,
                "fixed_versions": sorted(set(fixed_versions)),
                "fix_commit": fix_commit,
                "fix_source": "osv" if fix_commit else None,
                "references": refs,
            })
    return candidates, errors


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    candidates, errors = mine()
    with (OUT / "candidates_p2.jsonl").open("w") as fh:
        for c in candidates:
            fh.write(json.dumps(c) + "\n")
    with (OUT / "mining_errors_p2.jsonl").open("w") as fh:
        for e in errors:
            fh.write(json.dumps(e) + "\n")
    from collections import Counter
    by_cwe = Counter()
    for c in candidates:
        for w in c["cwes"]:
            by_cwe[w] += 1
    print(f"candidates={len(candidates)} errors={len(errors)}")
    print("by_cwe:", dict(sorted(by_cwe.items())))
    print("with_fix_commit:",
          sum(1 for c in candidates if c["fix_commit"]))


if __name__ == "__main__":
    main()
