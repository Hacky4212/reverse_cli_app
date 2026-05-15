from __future__ import annotations

import struct

from reverse_framework.core.context import AnalysisContext


ELF_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x64",
    183: "ARM64",
}


class ElfHeaderAnalyzer:
    name = "elf_header"

    def run(self, context: AnalysisContext) -> None:
        data = context.read_bytes()
        if len(data) < 20 or data[:4] != b"\x7fELF":
            return

        elf_class = data[4]
        endian_flag = data[5]
        endian = "<" if endian_flag == 1 else ">" if endian_flag == 2 else None
        if elf_class not in {1, 2} or endian is None:
            context.add_error(self.name, "Invalid ELF identification bytes.")
            return

        elf_type, machine, version = struct.unpack_from(f"{endian}HHI", data, 16)
        context.add_finding(
            self.name,
            {
                "class": "ELF32" if elf_class == 1 else "ELF64",
                "endian": "little" if endian == "<" else "big",
                "type": ELF_TYPES.get(elf_type, str(elf_type)),
                "machine": ELF_MACHINES.get(machine, str(machine)),
                "version": version,
            },
        )

