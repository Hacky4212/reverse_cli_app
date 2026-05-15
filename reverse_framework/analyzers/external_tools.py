from __future__ import annotations

import shutil
import subprocess

from reverse_framework.core.context import AnalysisContext
from reverse_framework.core.models import ToolStatus


class ExternalToolAnalyzer:
    name = "external_tools"

    def run(self, context: AnalysisContext) -> None:
        configured = context.config.external_tools
        if not configured:
            context.add_finding(
                self.name,
                {
                    "enabled": False,
                    "message": "No external tools configured.",
                },
            )
            return

        for name, command in configured.items():
            if not command:
                context.add_tool_status(
                    ToolStatus(
                        name=name,
                        command=[],
                        available=False,
                        enabled=True,
                        error="Command is empty.",
                    )
                )
                continue

            executable = command[0]
            if shutil.which(executable) is None:
                context.add_tool_status(
                    ToolStatus(
                        name=name,
                        command=command,
                        available=False,
                        enabled=True,
                        error=f"Executable not found: {executable}",
                    )
                )
                continue

            rendered = [part.replace("{target}", str(context.target)) for part in command]
            try:
                completed = subprocess.run(
                    rendered,
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:
                context.add_tool_status(
                    ToolStatus(
                        name=name,
                        command=rendered,
                        available=True,
                        enabled=True,
                        error=str(exc),
                    )
                )
                continue

            output = completed.stdout.strip() or completed.stderr.strip()
            context.add_tool_status(
                ToolStatus(
                    name=name,
                    command=rendered,
                    available=True,
                    enabled=True,
                    output=output[:8000],
                    error=None if completed.returncode == 0 else f"Exit code {completed.returncode}",
                )
            )

        context.add_finding(
            self.name,
            {
                "enabled": True,
                "tool_count": len(context.tools),
            },
        )

