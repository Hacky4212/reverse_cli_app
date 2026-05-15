import json
import sys
from pathlib import Path

from reverse_framework.analyzers.native_probe import NativeProbeAnalyzer
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.context import AnalysisContext


def test_native_probe_records_missing_tool(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(native_probe_path=str(tmp_path / "missing-native-probe")),
    )

    NativeProbeAnalyzer(path=context.config.native_probe_path).run(context)

    assert context.tools[0].available is False
    assert context.findings["native_probe"]["available"] is False


def test_native_probe_records_json_output(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    fake_probe = tmp_path / "fake_probe.py"
    fake_probe.write_text(
        "import json\n"
        "import sys\n"
        "print(json.dumps({"
        "'tool': 'native_probe', "
        "'target': sys.argv[1], "
        "'format': 'PE', "
        "'valid': True"
        "}))\n",
        encoding="utf-8",
    )
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(native_probe_path=sys.executable),
    )

    NativeProbeAnalyzer(path=sys.executable, extra_args=[str(fake_probe)]).run(context)

    assert context.findings["native_probe"]["format"] == "PE"
    assert context.tools[0].available is True
