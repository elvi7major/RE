import idaapi
import idautils
import idc

# You can change the highlight color here (red)
HIGHLIGHT_COLOR = 0x0000FF  # Red


def is_flower_block(start_ea):
    """
    Check if the instructions match the expected FLOWER pattern.
    Return (True, adr_target, subs_value, adds_value) if match, else (False, None, None, None).
    """
    expected_mnemonics = [
        "stp",  # 1. STP X0, X1, [SP,#-32]!
        "stp",  # 2. STP X2, X30, [SP,#16]
        "adr",  # 3. ADR X1, SOME_ADDRESS
        "subs", # 4. SUBS X1, X1, #value
        "mov",  # 5. MOV X0, X1
        "adds", # 6. ADDS X0, X0, #value
        "str",  # 7. STR X0, [SP,#24]
        "ldp",  # 8. LDP X2, X9, [SP,#16]
        "ldp",  # 9. LDP X0, X1, [SP],#0x20
        "br"    # 10. BR X9
    ]

    ea = start_ea
    adr_target = None
    subs_value = None
    adds_value = None

    for idx, expected in enumerate(expected_mnemonics):
        if not idc.is_code(idc.get_full_flags(ea)):
            return False, None, None, None

        mnem = idc.print_insn_mnem(ea).lower()
        if mnem != expected:
            return False, None, None, None

        if idx == 2 and mnem == "adr":
            opnd = idc.print_operand(ea, 1)
            if opnd.startswith("0x"):
                adr_target = int(opnd, 16)
            else:
                adr_target = idc.get_operand_value(ea, 1)
        if idx == 3 and mnem == "subs":
            subs_value = idc.get_operand_value(ea, 2)
        if idx == 5 and mnem == "adds":
            adds_value = idc.get_operand_value(ea, 2)

        ea = idc.next_head(ea)

    if adr_target is None or subs_value is None or adds_value is None:
        return False, None, None, None

    return True, adr_target, subs_value, adds_value


def highlight_instructions(start_ea, num_instructions):
    """
    Highlight the given instructions in IDA Pro
    """
    ea = start_ea
    for _ in range(num_instructions):
        idc.set_color(ea, idc.CIC_ITEM, HIGHLIGHT_COLOR)
        ea = idc.next_head(ea)


def calc_jump_addr(addr, subs, adds):
    return hex(addr - subs + adds)


def patch_flower_block(start_ea, real_target):
    """
    Smart patch:
    - NOP first 8 instructions
    - Patch last instructions to direct jump (B real_target)
    """
    ea = start_ea
    for i in range(8):
        idc.patch_dword(ea, 0xD503201F)  # ARM64 NOP
        ea = idc.next_head(ea)

    # Now insert branch
    b_offset = (real_target - ea) >> 2  # branch instruction needs offset divided by 4
    if -0x800000 <= b_offset <= 0x7FFFFF:
        # Make "B real_target"
        branch_insn = 0x14000000 | (b_offset & 0xFFFFFF)
        idc.patch_dword(ea, branch_insn)
        print(f"✅ Patched B to 0x{real_target:X} at 0x{ea:X}")
    else:
        print(f"❌ Cannot patch: target too far from 0x{ea:X} to 0x{real_target:X}")
    # Next instruction (after branch) also NOP
    ea = idc.next_head(ea)
    idc.patch_dword(ea, 0xD503201F)


def main():
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        print("❌ .text segment not found.")
        return

    ea = seg.start_ea
    end = seg.end_ea
    results = []
    idx = 1

    while ea < end:
        match, adr_target, subs_value, adds_value = is_flower_block(ea)
        if match:
            start_addr = ea
            for _ in range(10):
                ea = idc.next_head(ea)
            end_addr = ea
            jmp_addr = calc_jump_addr(adr_target, subs_value, adds_value)

            results.append((idx, start_addr, end_addr, adr_target, subs_value, adds_value, jmp_addr))

            # Add comment at the start
            idc.set_cmt(start_addr, "🌸 Potential FLOWER obfuscation block", 1)
            patch_flower_block(start_addr, int(jmp_addr, 16))

            # Highlight block
            highlight_instructions(start_addr, 10)

            idx += 1
        else:
            ea = idc.next_head(ea)

    print("\n=== 🎯 Found FLOWER matches ===")
    for (i, start, end, adr, subs, adds, jmp) in results:
        print(f"{i}: start=0x{start:X}, end=0x{end:X}, adr_target=0x{adr:X}, subs_value={subs}, adds_value={adds}, jmp_addr={jmp}")


if __name__ == "__main__":
    main()
