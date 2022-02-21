import os

import unicorn

ROM = "/Users/rickmark/Developer/hekapooios.github.io/resources/APROM/SecureROM for t8012si, iBoot-3401.0.0.1.16"
ROM_BASE = 0x100000000
ROM_SIZE = 0x100000
SRAM_BASE = 0x180000000
SRAM_SIZE = 0x200000


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))


def trace_new_edge(uc, cur, prev, data):
    print(
        f">>> Getting a new edge from {hex(prev.pc + prev.size - 1)} to {hex(cur.pc)}"
    )


def trace_tcg_sub(uc, address, arg1, arg2, data):
    print(f">>> Get a tcg sub opcode at {hex(address)} with args: {arg1} and {arg2}")


def trace_insn_invalid(uc, address, *args):
    print(f">>> Invalid Instruction @ 0x{address:x}: {args.join(',')}")


def test_load_securerom_unicorn():
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    os.path.getsize(ROM)
    uc.mem_map(ROM_BASE, ROM_SIZE, unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)
    with open(ROM, "rb") as secure_rom:
        uc.mem_write(ROM_BASE, secure_rom.read())

    uc.mem_map(SRAM_BASE, SRAM_SIZE)

    # tracing all basic blocks with customized callback
    uc.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)

    # tracing one instruction with customized callback
    uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    uc.hook_add(unicorn.UC_HOOK_INSN_INVALID, trace_insn_invalid)

    uc.emu_start(ROM_BASE, ROM_BASE + ROM_SIZE)

    print(f"IP: {uc.reg_read(unicorn.unicorn.arm64_const.UC_ARM64_REG_PC):x}")
