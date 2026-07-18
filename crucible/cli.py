"""CLI entry point: ``crucible scan <file>``.

Glues the static, dynamic, and reporting pipelines together. Keeps the
orchestration simple and ensures a single failing analyzer doesn't kill
the whole run.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from crucible import __version__
from crucible.dynamic import sandbox
from crucible.report import json_report, markdown_report, mitre, scorer
from crucible.static import elf as elf_mod
from crucible.static import entropy as entropy_mod
from crucible.static import hashes, pe as pe_mod, strings as strings_mod
from crucible.static import yara_scan
from crucible.utils.filetype import sniff
from crucible.utils.logging import get_logger

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
DEFAULT_REPORTS_DIR = Path("reports")


def _safe_call(fn, *args, logger, label: str, default=None, **kwargs):
    """Run ``fn``; log and continue if it raises."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        logger.error("%s failed: %s", label, exc)
        logger.debug("%s traceback:\n%s", label, traceback.format_exc())
        return default if default is not None else {"error": str(exc)}


def _run_static(target: Path, rules_dir: Path, logger) -> Dict[str, Any]:
    """Run every static analyzer and return a combined dict."""
    logger.info("[static] hashing")
    result: Dict[str, Any] = {}
    result["hashes"] = _safe_call(hashes.hash_file, target,
                                  logger=logger, label="hashing", default={})

    ftype = sniff(target)
    logger.info("[static] file type: %s", ftype.kind)

    if ftype.kind == "pe":
        result["pe"] = _safe_call(pe_mod.parse, target,
                                  logger=logger, label="PE parse", default={})
    elif ftype.kind == "elf":
        result["elf"] = _safe_call(elf_mod.parse, target,
                                   logger=logger, label="ELF parse", default={})

    binary_result = result.get("pe") or result.get("elf") or {}
    if binary_result.get("parsed"):
        result["section_summary"] = entropy_mod.summarize_sections(
            binary_result.get("sections", [])
        )

    logger.info("[static] extracting strings")
    string_findings = _safe_call(strings_mod.analyze, target,
                                 logger=logger, label="strings",
                                 default=None)
    if string_findings is not None:
        result["strings"] = strings_mod.as_dict(string_findings)

    logger.info("[static] running YARA")
    result["yara"] = _safe_call(yara_scan.scan, target, rules_dir,
                                logger=logger, label="YARA",
                                default={"available": False, "matches": []})

    return result


def _build_findings(target: Path, static: Dict[str, Any],
                    dynamic: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble the full findings dict with scoring and MITRE mapping."""
    ftype = sniff(target)
    size = target.stat().st_size

    base = {
        "meta": {
            "tool": "crucible",
            "version": __version__,
            "path": str(target.resolve()),
            "size": size,
            "filetype": ftype.kind,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "static": static,
        "dynamic": dynamic,
    }

    score_result = scorer.score(base)
    base["scoring"] = {
        "score": score_result.score,
        "label": score_result.label,
        "indicators": score_result.indicators,
        "breakdown": score_result.breakdown,
    }
    base["mitre"] = mitre.techniques_for(score_result.indicators)
    return base


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the ``scan`` subcommand."""
    logger = get_logger(verbose=args.verbose)

    target = Path(args.file).resolve()
    if not target.is_file():
        logger.error("not a file: %s", target)
        return 2

    logger.info("scanning %s", target)

    static_findings = _run_static(target, Path(args.rules), logger)

    if args.no_dynamic:
        dynamic_findings = {"ran": False, "reason": "disabled via --no-dynamic"}
    else:
        ftype = sniff(target)
        try:
            logger.info("[dynamic] launching sandbox (timeout=%ss)", args.timeout)
            result = sandbox.run(target, ftype, timeout=args.timeout)
            dynamic_findings = result.to_dict()
        except Exception as exc:
            logger.error("dynamic stage failed: %s", exc)
            logger.debug("traceback:\n%s", traceback.format_exc())
            dynamic_findings = {"ran": False, "reason": f"exception: {exc}"}

    findings = _build_findings(target, static_findings, dynamic_findings)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = target.stem + "_" + findings["static"].get("hashes", {}).get("sha256", "nohash")[:12]
    json_path = out_dir / f"{stem}.json"
    md_path = out_dir / f"{stem}.md"

    json_report.write(findings, json_path)
    markdown_report.write(findings, md_path)

    logger.info("wrote %s", json_path)
    logger.info("wrote %s", md_path)

    score = findings["scoring"]["score"]
    label = findings["scoring"]["label"]
    print(f"Suspicion score: {score}/100 ({label})")
    print(f"JSON report:    {json_path}")
    print(f"Markdown report: {md_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top level argparse parser."""
    parser = argparse.ArgumentParser(
        prog="crucible",
        description="throw a sketchy file at it, get a score back.",
    )
    parser.add_argument("--version", action="version", version=f"crucible {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file and write a report.")
    scan.add_argument("file", help="path to the file you want to look at.")
    scan.add_argument("--no-dynamic", action="store_true",
                      help="skip the dynamic stage, don't run the file.")
    scan.add_argument("--timeout", type=int, default=15,
                      help="how long to let it run in seconds (default: 15).")
    scan.add_argument("--output", default=str(DEFAULT_REPORTS_DIR),
                      help="where reports go.")
    scan.add_argument("--rules", default=str(DEFAULT_RULES_DIR),
                      help="folder with yara rule files.")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="chattier logs.")
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None) -> int:
    """Main CLI entrypoint. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
