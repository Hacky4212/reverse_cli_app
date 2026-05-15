import sys
from pathlib import Path

from reverse_framework.api import analyze_process_memory, available_analyzers
from reverse_framework.analyzers.process_memory import ProcessMemoryAnalyzer
from reverse_framework.core.config import TriageConfig
from reverse_framework.core.context import AnalysisContext


def test_available_analyzers_include_process_memory() -> None:
    assert "process_memory" in available_analyzers()


def test_process_memory_records_missing_tool(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"")
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(
            process_memory_path=str(tmp_path / "missing-process-memory-reader"),
            process_memory_pid=4321,
            process_memory_address="0x1000",
        ),
    )

    ProcessMemoryAnalyzer(path=context.config.process_memory_path).run(context)

    assert context.tools[0].available is False
    assert context.findings["process_memory"]["available"] is False


def test_process_memory_records_json_output(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"")
    fake_reader = tmp_path / "fake_reader.py"
    fake_reader.write_text(
        "import json\n"
        "import sys\n"
        "pid = int(sys.argv[sys.argv.index('--pid') + 1])\n"
        "address = sys.argv[sys.argv.index('--address') + 1]\n"
        "size = int(sys.argv[sys.argv.index('--size') + 1])\n"
        "print(json.dumps({"
        "'tool': 'process_memory_reader', "
        "'pid': pid, "
        "'address': address, "
        "'requested_size': size, "
        "'read_size': size, "
        "'limited': False, "
        "'success': True, "
        "'partial': False, "
        "'region': None, "
        "'data_hex': '41 42', "
        "'data_ascii': 'AB', "
        "'error': None"
        "}))\n",
        encoding="utf-8",
    )
    context = AnalysisContext(
        target=sample,
        config=TriageConfig(
            process_memory_path=sys.executable,
            process_memory_pid=4321,
            process_memory_address="0x1000",
            process_memory_size=2,
        ),
    )

    ProcessMemoryAnalyzer(path=sys.executable, extra_args=[str(fake_reader)]).run(context)

    payload = context.findings["process_memory"]
    assert payload["pid"] == 4321
    assert payload["address"] == "0x1000"
    assert payload["data_ascii"] == "AB"
    assert context.tools[0].available is True


def test_analyze_process_memory_uses_input_values(tmp_path: Path) -> None:
    fake_reader = tmp_path / "fake_reader.py"
    fake_reader.write_text(
        "import json\n"
        "import sys\n"
        "pid = int(sys.argv[sys.argv.index('--pid') + 1])\n"
        "address = sys.argv[sys.argv.index('--address') + 1]\n"
        "size = int(sys.argv[sys.argv.index('--size') + 1])\n"
        "print(json.dumps({"
        "'tool': 'process_memory_reader', "
        "'pid': pid, "
        "'address': address, "
        "'requested_size': size, "
        "'read_size': size, "
        "'limited': False, "
        "'success': True, "
        "'partial': False, "
        "'region': None, "
        "'data_hex': '41 42', "
        "'data_ascii': 'AB', "
        "'error': None"
        "}))\n",
        encoding="utf-8",
    )

    result = analyze_process_memory(
        4321,
        "0x1000",
        size=2,
        config=TriageConfig(
            process_memory_path=sys.executable,
            process_memory_extra_args=[str(fake_reader)],
        ),
        analyzers=["process_memory"],
    )

    payload = result.findings["process_memory"]
    assert payload["pid"] == 4321
    assert payload["address"] == "0x1000"
    assert payload["data_ascii"] == "AB"
