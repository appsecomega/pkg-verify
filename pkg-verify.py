#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkg-verify.py (OOP / Clean Code)

- Consulta NVD (CVE) e GHSA (GitHub Advisory) para um pacote (sempre ambos)
- Mescla NVD+GHSA quando for o mesmo problema (sem duplicar por fonte)
- Aceita purl ou nome simples
- --pkg-mng/-pm/-p define o ecossistema (npm, pip, maven, nuget, etc.). Se omitido, GHSA busca em todos.
- --version/-v filtra e EXIBE APENAS o que atinge essa versão (GHSA usa affects=pkg@versão)
- Exporta JSON (--json) e XLSX (--xlsx)
- Lê credenciais de config.yaml por padrão; --config sobrescreve

Instalação:
    pip install requests pyyaml rich pandas openpyxl
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

# ---------- Utils / Constants ----------

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_ADVISORIES_API = "https://api.github.com/advisories"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, None: 4}

SEMVER_RX = re.compile(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")
RANGE_HYPHEN_RX = re.compile(r"^\s*v?(\d+(?:\.\d+){0,2})\s*-\s*v?(\d+(?:\.\d+){0,2})\s*$")
CMP_RX = re.compile(r"^(<=|>=|<|>|==|=)\s*v?([^\s]+)\s*$")

DESC_OPS = [
    (re.compile(r"\b(before|prior to)\s*v?(\d+(?:\.\d+){0,2})", re.I), lambda m: f"< {m.group(2)}"),
    (re.compile(r"\bthrough\s*v?(\d+(?:\.\d+){0,2})", re.I), lambda m: f"<= {m.group(1)}"),
    (
        re.compile(r"\bfrom\s*v?(\d+(?:\.\d+){0,2})\s+through\s*v?(\d+(?:\.\d+){0,2})", re.I),
        lambda m: f">= {m.group(1)}, <= {m.group(2)}",
    ),
    (re.compile(r"(<=|>=|<|>|==|=)\s*v?(\d+(?:\.\d+){0,2})"), lambda m: f"{m.group(1)} {m.group(2)}"),
]


# ---------- Config ----------

class ConfigLoader:
    def __init__(self, path: str):
        self._config: Dict[str, Any] = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            self._config = {}
        except Exception as e:
            console.print(f"[yellow][warn][/yellow] Falha ao ler config '{path}': {e}")
            self._config = {}

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._config.get(key, default)


# ---------- PURL ----------

def parse_purl(s: str) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Retorna (ecosystem | None, name, version | None).
    Não assume ecosystem se não for PURL.
    """
    s = s.strip()
    if s.startswith("pkg:"):
        m = re.match(r"^pkg:(?P<eco>[^/]+)/(?P<name>[^@]+)(?:@(?P<ver>.+))?$", s)
        if not m:
            raise ValueError(f"PURL inválido: {s}")
        eco = (m.group("eco") or "").lower() or None
        name = (m.group("name") or "").replace("%40", "@")
        ver = m.group("ver")
        return eco, name, ver
    return None, s, None


# ---------- Version / Range (Value Objects) ----------

@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int = 0
    patch: int = 0

    @staticmethod
    def parse(v: str) -> "SemVer":
        m = SEMVER_RX.match(v.strip())
        if not m:
            nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
            while len(nums) < 3:
                nums.append(0)
            return SemVer(*nums[:3])
        return SemVer(int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))

    def __lt__(self, other: "SemVer") -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __le__(self, other: "SemVer") -> bool:
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)

    def __gt__(self, other: "SemVer") -> bool:
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)

    def __ge__(self, other: "SemVer") -> bool:
        return (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return False
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)


class VersionRange:
    """Interpreta ranges: AND por vírgulas, OR com '||'/' or ', e intervalo com hífen."""

    @staticmethod
    def _normalize_segment(seg: str) -> List[str]:
        seg = seg.strip()
        m = RANGE_HYPHEN_RX.match(seg)
        if m:
            return [f">= {m.group(1)}", f"<= {m.group(2)}"]
        parts = [p.strip() for p in seg.split(",") if p.strip()]
        return parts if parts else [seg]

    @staticmethod
    def _cmp(version: str, comparator: str) -> bool:
        m = CMP_RX.match(comparator)
        if not m:
            return False
        op, bound = m.group(1), m.group(2)
        v = SemVer.parse(version)
        b = SemVer.parse(bound)
        if op == "<":
            return v < b
        if op == "<=":
            return v <= b
        if op == ">":
            return v > b
        if op == ">=":
            return v >= b
        if op in ("=", "=="):
            return v == b
        return False

    @staticmethod
    def matches(version: Optional[str], range_str: Optional[str]) -> bool:
        if not version or not range_str:
            return False
        groups = re.split(r"\s*\|\|\s*|\s+or\s+", str(range_str))
        for g in groups:
            comps = VersionRange._normalize_segment(g)
            if all(VersionRange._cmp(version, c) for c in comps):
                return True
        return False

    @staticmethod
    def any_match(version: Optional[str], affected_range: Optional[str]) -> bool:
        if not version or not affected_range:
            return False
        blocks = [b.strip() for b in affected_range.split("|") if b.strip()]
        return any(VersionRange.matches(version, blk) for blk in blocks)


# ---------- Models ----------

@dataclass
class Advisory:
    source: str  # "NVD" | "GitHub" | "NVD+GitHub" (após merge)
    cve: Optional[str]
    ghsa: Optional[str]
    severity: Optional[str]
    published: Optional[str]
    matches_version: Optional[bool]
    affected_range: Optional[str]
    first_patched: Optional[str]
    summary: Optional[str]
    references: List[str] = field(default_factory=list)


# ---------- Clients (Gateways) ----------

class NvdClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    @staticmethod
    def _pick_summary(descs: List[Dict[str, Any]]) -> str:
        if not descs:
            return ""
        en = [d for d in descs if d.get("lang") == "en"]
        return (en[0] if en else descs[0]).get("value", "")

    @staticmethod
    def _range_from_cpe_match(match: Dict[str, Any]) -> Optional[str]:
        if not match.get("vulnerable", False):
            return None
        parts = []
        if "versionStartIncluding" in match:
            parts.append(f">= {match['versionStartIncluding']}")
        if "versionStartExcluding" in match:
            parts.append(f"> {match['versionStartExcluding']}")
        if "versionEndIncluding" in match:
            parts.append(f"<= {match['versionEndIncluding']}")
        if "versionEndExcluding" in match:
            parts.append(f"< {match['versionEndExcluding']}")
        if parts:
            return ", ".join(parts)
        version = match.get("version")
        if version and str(version).lower() not in ("*", "-"):
            return f"= {version}"
        return None

    @staticmethod
    def _extract_ranges_from_description(text: str) -> List[str]:
        if not text:
            return []
        ranges: List[str] = []
        for rx, fmt in DESC_OPS:
            for m in rx.finditer(text):
                try:
                    ranges.append(fmt(m))
                except Exception:
                    pass
        # dedup
        seen, uniq = set(), []
        for r in ranges:
            if r not in seen:
                seen.add(r)
                uniq.append(r)
        return uniq

    def _collect_affected_ranges(self, v_item: Dict[str, Any]) -> Optional[str]:
        ranges: List[str] = []
        conf = v_item.get("configurations") or {}
        nodes = conf.get("nodes", [])
        if isinstance(nodes, list):
            for node in nodes:
                matches = (node or {}).get("cpeMatch", [])
                if isinstance(matches, list):
                    for m in matches:
                        if isinstance(m, dict):
                            r = self._range_from_cpe_match(m)
                            if r:
                                ranges.append(r)
        if not ranges:
            cve = v_item.get("cve", {}) or {}
            desc_text = self._pick_summary(cve.get("descriptions", []) if isinstance(cve.get("descriptions"), list) else [])
            ranges = self._extract_ranges_from_description(desc_text)
        if not ranges:
            return None
        # dedup
        seen, out = set(), []
        for r in ranges:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return " | ".join(out[:8])

    def search(self, keyword: str, version: Optional[str]) -> List[Advisory]:
        params = {"keywordSearch": keyword, "resultsPerPage": 200}
        headers = {"apiKey": self.api_key} if self.api_key else {}
        r = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", []) or []

        results: List[Advisory] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = v.get("cve", {}) if isinstance(v.get("cve"), dict) else {}
            metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
            severity = None
            if isinstance(metrics.get("cvssMetricV31"), list) and metrics["cvssMetricV31"]:
                severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity")
            elif isinstance(metrics.get("cvssMetricV30"), list) and metrics["cvssMetricV30"]:
                severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity")
            elif isinstance(metrics.get("cvssMetricV2"), list) and metrics["cvssMetricV2"]:
                severity = metrics["cvssMetricV2"][0].get("baseSeverity")

            affected = self._collect_affected_ranges(v)
            match = VersionRange.any_match(version, affected) if version else None

            summary = self._pick_summary(cve.get("descriptions", []) if isinstance(cve.get("descriptions"), list) else [])
            refs = cve.get("references", []) if isinstance(cve.get("references"), list) else []

            results.append(
                Advisory(
                    source="NVD",
                    cve=cve.get("id"),
                    ghsa=None,
                    severity=severity,
                    published=cve.get("published"),
                    matches_version=match,
                    affected_range=affected,
                    first_patched=None,
                    summary=summary,
                    references=[(ref.get("url") or ref.get("source") or ref.get("name")) for ref in refs if isinstance(ref, dict)],
                )
            )
        return results


class GhsaClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token

    @staticmethod
    def _normalize_refs(refs_raw: Any) -> List[str]:
        refs: List[str] = []
        if isinstance(refs_raw, list):
            for ref in refs_raw:
                if isinstance(ref, dict):
                    url = ref.get("url") or ref.get("source") or ref.get("name")
                    if url:
                        refs.append(url)
                else:
                    refs.append(str(ref))
        elif isinstance(refs_raw, dict):
            url = refs_raw.get("url") or refs_raw.get("source") or refs_raw.get("name")
            if url:
                refs.append(url)
        elif refs_raw:
            refs.append(str(refs_raw))
        return refs

    def search(self, name: str, ecosystem: Optional[str], version: Optional[str], per_page: int = 100) -> List[Advisory]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params = {
            "per_page": min(max(per_page, 1), 100),
            "type": "reviewed",
            "affects": f"{name}@{version}" if version else name,
        }
        if ecosystem:
            params["ecosystem"] = ecosystem

        r = requests.get(GH_ADVISORIES_API, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        items = r.json()
        if not isinstance(items, list):
            items = []

        results: List[Advisory] = []
        for adv in items:
            if not isinstance(adv, dict):
                continue
            vulns = adv.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                continue

            for vul in vulns:
                if not isinstance(vul, dict):
                    continue
                pkg_data = vul.get("package") or {}
                if not isinstance(pkg_data, dict):
                    continue

                pkg = (pkg_data.get("name") or "").lower()
                eco = (pkg_data.get("ecosystem") or "").lower()
                if ecosystem and eco != ecosystem.lower():
                    continue
                if pkg != name.lower():
                    continue

                affected_range = vul.get("vulnerable_version_range") or ""
                if not isinstance(affected_range, str):
                    affected_range = str(affected_range)

                fpv = vul.get("first_patched_version")
                first_patched = fpv.get("identifier") if isinstance(fpv, dict) else (str(fpv) if fpv else None)

                results.append(
                    Advisory(
                        source="GitHub",
                        cve=adv.get("cve_id"),
                        ghsa=adv.get("ghsa_id"),
                        severity=adv.get("severity"),
                        published=adv.get("published_at"),
                        matches_version=True if version else None,  # já filtrado por affects
                        affected_range=affected_range or None,
                        first_patched=first_patched,
                        summary=(adv.get("summary") or ""),
                        references=self._normalize_refs(adv.get("references")),
                    )
                )
        return results


# ---------- Merge ----------

def _parse_date_safe(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


class AdvisoryMerger:
    """Agrupa por (CVE, GHSA), agregando campos e fontes."""

    @staticmethod
    def merge(items: Iterable[Advisory]) -> List[Advisory]:
        merged: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for it in items:
            cve = (it.cve or "").strip()
            ghsa = (it.ghsa or "").strip()
            key = (cve, ghsa)

            if key not in merged:
                merged[key] = {
                    "sources": {it.source},
                    "cve": it.cve or None,
                    "ghsa": it.ghsa or None,
                    "severity": (it.severity or None),
                    "published": it.published,
                    "matches_version": it.matches_version,
                    "affected_range": it.affected_range,
                    "first_patched": it.first_patched,
                    "summary": it.summary,
                    "references": list(it.references or []),
                }
                continue

            m = merged[key]
            m["sources"].add(it.source)

            # severity: pega a mais alta
            s_a = (m.get("severity") or "").upper() or None
            s_b = (it.severity or "").upper() or None
            if SEV_ORDER.get(s_b, 4) < SEV_ORDER.get(s_a, 4):
                m["severity"] = s_b

            # published: mais antiga
            da, db = _parse_date_safe(m.get("published")), _parse_date_safe(it.published)
            if da and db:
                m["published"] = (da if da <= db else db).isoformat()
            elif db and not da:
                m["published"] = db.isoformat()

            # matches_version: True se qualquer for True
            mv_a, mv_b = m.get("matches_version"), it.matches_version
            m["matches_version"] = True if (mv_a is True or mv_b is True) else (mv_a if mv_a is not None else mv_b)

            # affected_range: união dedup
            rngs: List[str] = []
            for r in [m.get("affected_range"), it.affected_range]:
                if r:
                    rngs.extend([s.strip() for s in str(r).split("|") if s.strip()])
            if rngs:
                seen, uniq = set(), []
                for r in rngs:
                    if r not in seen:
                        seen.add(r)
                        uniq.append(r)
                m["affected_range"] = " | ".join(uniq[:12])

            # first_patched: preferir GHSA
            if (m.get("first_patched") is None) or (it.source == "GitHub" and it.first_patched):
                m["first_patched"] = it.first_patched or m.get("first_patched")

            # summary: preferir GHSA
            if it.source == "GitHub" and it.summary:
                m["summary"] = it.summary or m.get("summary")

            # references: união dedup
            refs = (m.get("references") or []) + (it.references or [])
            seen, out = set(), []
            for r in refs:
                if r not in seen:
                    seen.add(r)
                    out.append(r)
            m["references"] = out

        # construir finais
        finals: List[Advisory] = []
        for data in merged.values():
            fonte = "+".join(sorted([s for s in data["sources"] if s])) or "—"
            finals.append(
                Advisory(
                    source=fonte,
                    cve=data.get("cve"),
                    ghsa=data.get("ghsa"),
                    severity=data.get("severity"),
                    published=data.get("published"),
                    matches_version=data.get("matches_version"),
                    affected_range=data.get("affected_range"),
                    first_patched=data.get("first_patched"),
                    summary=data.get("summary"),
                    references=data.get("references") or [],
                )
            )
        return finals


# ---------- Rendering ----------

class TableRenderer:
    SEV_STYLES = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MODERATE": "bold yellow",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }

    def render(self, items: List[Advisory], version: Optional[str]) -> None:
        if not items:
            console.print(
                "[bold green]Nenhuma vulnerabilidade encontrada para a versão informada.[/bold green]"
                if version
                else "[bold green]Nenhuma vulnerabilidade encontrada.[/bold green]"
            )
            return

        table = Table(
            title=f"Vulnerabilidades Encontradas{f' (versão={version})' if version else ''}",
            box=box.MINIMAL_DOUBLE_HEAD,
            show_lines=True,
        )
        table.add_column("Fonte", style="cyan", no_wrap=True)
        table.add_column("CVE", style="magenta", no_wrap=True)
        table.add_column("GHSA", style="magenta", no_wrap=True)
        table.add_column("Sev.", style="bold", no_wrap=True)
        table.add_column("Publicada", style="dim", no_wrap=True)
        table.add_column("Atinge Versão?", style="bold", no_wrap=True)
        table.add_column("Faixa Afetada", style="white")
        table.add_column("Primeira Corrigida", style="white", no_wrap=True)
        table.add_column("Resumo", style="white")

        def sort_key(x: Advisory):
            sev = (x.severity or "").upper()
            pub = x.published or ""
            return (SEV_ORDER.get(sev, 4), pub)

        for r in sorted(items, key=sort_key):
            sev = (r.severity or "").upper() or "N/A"
            sev_style = self.SEV_STYLES.get(sev, "white")
            mv = r.matches_version
            mv_str = "—"
            if mv is True:
                mv_str = "[bold green]SIM[/bold green]"
            elif mv is False:
                mv_str = "[bold red]NÃO[/bold red]"

            summary = (r.summary or "").replace("\n", " ")[:140]

            table.add_row(
                r.source,
                r.cve or "",
                r.ghsa or "",
                f"[{sev_style}] {sev} [/{sev_style}]",
                r.published or "N/A",
                mv_str,
                r.affected_range or "—",
                r.first_patched or "—",
                summary,
            )

        console.print(table)
        console.print(f"[bold]Total:[/bold] {len(items)}")


# ---------- Export (Strategy) ----------

class Exporter:
    def export(self, items: List[Advisory], path: str) -> None:
        raise NotImplementedError


class JsonExporter(Exporter):
    def export(self, items: List[Advisory], path: str) -> None:
        data = [
            {
                "source": it.source,
                "cve": it.cve,
                "ghsa": it.ghsa,
                "severity": it.severity,
                "published": it.published,
                "matches_version": it.matches_version,
                "affected_range": it.affected_range,
                "first_patched": it.first_patched,
                "summary": it.summary,
                "references": it.references,
            }
            for it in items
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✔ JSON salvo em:[/green] {path}")


class XlsxExporter(Exporter):
    def __init__(self):
        try:
            import pandas as pd  # type: ignore
            self.pd = pd
        except Exception:
            self.pd = None

    def export(self, items: List[Advisory], path: str) -> None:
        if self.pd is None:
            raise RuntimeError("pandas não instalado. Rode: pip install pandas openpyxl")
        rows = [
            {
                "source": it.source,
                "cve": it.cve,
                "ghsa": it.ghsa,
                "severity": it.severity,
                "published": it.published,
                "matches_version": it.matches_version,
                "affected_range": it.affected_range,
                "first_patched": it.first_patched,
                "summary": it.summary,
                "references": "\n".join(it.references or []),
            }
            for it in items
        ]
        df = self.pd.DataFrame(rows, columns=[
            "source", "cve", "ghsa", "severity", "published",
            "matches_version", "affected_range", "first_patched", "summary", "references"
        ])
        df.to_excel(path, index=False)
        console.print(f"[green]✔ XLSX salvo em:[/green] {path}")


class ExporterFacade:
    def __init__(self):
        self.json_exporter = JsonExporter()
        self.xlsx_exporter = XlsxExporter()

    def export(self, items: List[Advisory], json_path: Optional[str], xlsx_path: Optional[str]) -> None:
        if json_path:
            self.json_exporter.export(items, json_path)
        if xlsx_path:
            self.xlsx_exporter.export(items, xlsx_path)


# ---------- Application Facade ----------

class PackageVulnCheckerApp:
    def __init__(self, nvd_key: Optional[str], gh_token: Optional[str]):
        self.nvd = NvdClient(api_key=nvd_key)
        self.ghsa = GhsaClient(token=gh_token)
        self.renderer = TableRenderer()
        self.exporter = ExporterFacade()

    def run(
        self,
        package: str,
        ecosystem: Optional[str],
        version: Optional[str],
        json_path: Optional[str],
        xlsx_path: Optional[str],
    ) -> None:
        eco_from_purl, name, ver_from_purl = parse_purl(package)
        ecosystem = ecosystem or eco_from_purl
        version = version or ver_from_purl

        extras = []
        if ecosystem:
            extras.append(f"ecosystem={ecosystem}")
        if version:
            extras.append(f"version={version}")
        console.print(f"[cyan]>> Consultando '{name}'{(', ' + ', '.join(extras)) if extras else ''}[/cyan]")

        try:
            nvd_items = self.nvd.search(keyword=name, version=version)
        except Exception as e:
            console.print(f"[red][erro][/red] NVD: {e}")
            nvd_items = []

        try:
            ghsa_items = self.ghsa.search(name=name, ecosystem=ecosystem, version=version)
        except Exception as e:
            console.print(f"[red][erro][/red] GitHub Advisory: {e}")
            ghsa_items = []

        combined: List[Advisory] = nvd_items + ghsa_items

        # Com versão, manter apenas advisories que atingem a versão
        if version:
            filtered: List[Advisory] = []
            for it in combined:
                if it.source == "GitHub":
                    # GHSA já veio filtrado por affects=pkg@version
                    filtered.append(it)
                else:
                    if it.matches_version is True:
                        filtered.append(it)
            combined = filtered

        merged = AdvisoryMerger.merge(combined)
        self.renderer.render(merged, version)
        self.exporter.export(merged, json_path, xlsx_path)


# ---------- CLI ----------

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Checar vulnerabilidades no NVD e GitHub Advisory para um pacote.")
    p.add_argument("package", help="Nome do pacote ou purl")
    p.add_argument("-pm", "--pkg-mng", "-p", dest="pkg_mng", default=None, help="Gerenciador/eco (npm, pip, maven, nuget, etc.)")
    p.add_argument("-v", "--version", default=None, help="Versão do pacote (ex.: 1.2.3) — filtra e mostra APENAS o que atinge essa versão")
    p.add_argument("--config", default=None, help="Arquivo de configuração YAML (default: config.yaml)")
    p.add_argument("--nvd-api-key", default=None, help="API key NVD")
    p.add_argument("--github-token", default=None, help="Token GitHub")
    p.add_argument("--json", default=None, help="Caminho para exportar JSON (ex.: saida.json)")
    p.add_argument("--xlsx", default=None, help="Caminho para exportar XLSX (ex.: saida.xlsx)")
    return p


def main() -> None:
    args = build_cli().parse_args()

    config_path = args.config or "config.yaml"
    cfg = ConfigLoader(config_path)

    nvd_key = args.nvd_api_key or cfg.get("nvd_api_key") or os.getenv("NVD_API_KEY")
    gh_token = args.github_token or cfg.get("github_token") or os.getenv("GITHUB_TOKEN")

    app = PackageVulnCheckerApp(nvd_key=nvd_key, gh_token=gh_token)
    app.run(
        package=args.package,
        ecosystem=args.pkg_mng,
        version=args.version,
        json_path=args.json,
        xlsx_path=args.xlsx,
    )


if __name__ == "__main__":
    main()
