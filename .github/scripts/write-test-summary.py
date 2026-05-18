#!/usr/bin/env python3
"""Write a readable GitHub Actions summary for .NET TRX and Cobertura results."""

from __future__ import annotations

import glob
import html
import os
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path


RESULTS_DIR = Path(os.environ.get("TEST_RESULTS_DIR", "TestResults"))
COVERAGE_THRESHOLD = float(os.environ.get("COVERAGE_THRESHOLD", "0.80"))


def pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.2f}%"


def md_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return html.escape(text.replace("\n", " ").replace("\r", " ")).replace("|", "\\|")


def trx_namespace(root: ET.Element) -> dict[str, str]:
    if root.tag.startswith("{"):
        return {"trx": root.tag.split("}", 1)[0][1:]}
    return {"trx": ""}


def findall(root: ET.Element, path: str, ns: dict[str, str]) -> list[ET.Element]:
    if ns["trx"]:
        return root.findall(path, ns)
    return root.findall(path.replace("trx:", ""))


def find(root: ET.Element, path: str, ns: dict[str, str]) -> ET.Element | None:
    if ns["trx"]:
        return root.find(path, ns)
    return root.find(path.replace("trx:", ""))


def parse_trx_files() -> tuple[dict[str, int], list[dict[str, str]], list[str]]:
    counters = {
        "total": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "notExecuted": 0,
    }
    failures: list[dict[str, str]] = []
    files = sorted(RESULTS_DIR.glob("*.trx"))

    for path in files:
        root = ET.parse(path).getroot()
        ns = trx_namespace(root)
        counter = find(root, "trx:ResultSummary/trx:Counters", ns)
        if counter is not None:
            for key in counters:
                counters[key] += int(counter.attrib.get(key, "0"))

        for result in findall(root, ".//trx:UnitTestResult", ns):
            outcome = result.attrib.get("outcome", "")
            if outcome == "Passed":
                continue

            message = ""
            error_message = find(result, "trx:Output/trx:ErrorInfo/trx:Message", ns)
            if error_message is not None and error_message.text:
                message = error_message.text.strip()

            failures.append(
                {
                    "test": result.attrib.get("testName", ""),
                    "outcome": outcome or "Unknown",
                    "duration": result.attrib.get("duration", ""),
                    "message": message,
                }
            )

    return counters, failures, [str(path) for path in files]


def parse_coverage() -> tuple[float | None, float | None, list[dict[str, str]], str | None]:
    files = sorted(glob.glob(str(RESULTS_DIR / "**" / "coverage.cobertura.xml"), recursive=True), key=os.path.getmtime)
    if not files:
        return None, None, [], None

    coverage_file = files[-1]
    root = ET.parse(coverage_file).getroot()
    line_rate = float(root.attrib.get("line-rate", "0"))
    branch_rate = float(root.attrib.get("branch-rate", "0"))
    packages = []
    for package in root.findall("./packages/package"):
        packages.append(
            {
                "name": package.attrib.get("name", ""),
                "line": pct(float(package.attrib.get("line-rate", "0"))),
                "branch": pct(float(package.attrib.get("branch-rate", "0"))),
            }
        )

    return line_rate, branch_rate, packages, coverage_file


def main() -> int:
    counters, failures, trx_files = parse_trx_files()
    line_rate, branch_rate, packages, coverage_file = parse_coverage()

    tests_passed = counters["failed"] == 0 and not failures and bool(trx_files)
    coverage_passed = line_rate is not None and line_rate >= COVERAGE_THRESHOLD

    lines = [
        "# .NET Test Summary",
        "",
        "## Checks",
        "",
        "| Check | Result |",
        "| --- | --- |",
        f"| Test run | {'✅ Passed' if tests_passed else '❌ Failed'} |",
        f"| Line coverage threshold ({COVERAGE_THRESHOLD * 100:.0f}%) | {'✅ Passed' if coverage_passed else '❌ Failed'} |",
        "",
        "## Test Results",
        "",
        "| Total | Executed | Passed | Failed | Not executed |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {counters['total']} | {counters['executed']} | {counters['passed']} | {counters['failed']} | {counters['notExecuted']} |",
        "",
    ]

    if failures:
        lines.extend(
            [
                "## Failed Tests",
                "",
                "| Test | Outcome | Duration | Message |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for failure in failures[:25]:
            message = textwrap.shorten(failure["message"], width=300, placeholder="...")
            lines.append(
                f"| {md_escape(failure['test'])} | {md_escape(failure['outcome'])} | {md_escape(failure['duration'])} | {md_escape(message)} |"
            )
        if len(failures) > 25:
            lines.append(f"| ... | ... | ... | {len(failures) - 25} additional failures omitted from summary. See TRX artifact. |")
        lines.append("")
    else:
        lines.extend(["## Failed Tests", "", "| Result |", "| --- |", "| No failed tests. |", ""])

    lines.extend(
        [
            "## Coverage",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Line coverage | {pct(line_rate)} |",
            f"| Branch coverage | {pct(branch_rate)} |",
            "",
        ]
    )

    if packages:
        lines.extend(["### Coverage By Package", "", "| Package | Line | Branch |", "| --- | ---: | ---: |"])
        for package in packages:
            lines.append(f"| {md_escape(package['name'])} | {package['line']} | {package['branch']} |")
        lines.append("")

    lines.extend(["## Artifacts", "", "| Artifact | Path |", "| --- | --- |"])
    for trx_file in trx_files:
        lines.append(f"| TRX | `{md_escape(trx_file)}` |")
    if coverage_file:
        lines.append(f"| Cobertura coverage | `{md_escape(coverage_file)}` |")
    lines.append("")

    summary = "\n".join(lines)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summary)
            handle.write("\n")
    else:
        print(summary)

    if not coverage_passed:
        print(f"Line coverage is below threshold: {pct(line_rate)} < {COVERAGE_THRESHOLD * 100:.0f}%", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
