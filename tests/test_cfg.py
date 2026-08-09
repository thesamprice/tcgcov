"""Tests for the static branch inventory (tcgcov.cfg).

All fixtures are synthetic `objdump -d` text -- no toolchain required. The
MicroBlaze fixture is the important one: it is the reason this feature exists,
because its branches have delay slots and the fall-through address is therefore
NOT branch+4.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import cfg  # noqa: E402


def objdump(lines, fmt="elf32-microblazeel", section=".text"):
    """Build objdump -d text from (addr, raw, "mnemonic\\toperands") triples."""
    out = ["", "a.elf:     file format %s" % fmt, "",
           "Disassembly of section %s:" % section, ""]
    for item in lines:
        if isinstance(item, str):          # symbol header, verbatim
            out.append(item)
            continue
        addr, raw, text = item
        out.append("%8x:\t%s \t%s" % (addr, raw, text))
    return "\n".join(out) + "\n"


# MicroBlaze:
#   90000000  addik                     <- block 0 starts
#   90000004  beqid r6, 16   -> 90000014 <- conditional branch (HAS delay slot)
#   90000008  or   (delay slot)         <- block 0 ends here, executes either way
#   9000000c  addik                     <- FALL-THROUGH is here, not 90000008
#   90000010  bri  -> 9000001c          <- unconditional, no delay slot
#   90000014  addik                     <- taken target
#   90000018  addik
#   9000001c  rtsd (delayed return)
#   90000020  or   (delay slot)
MB_TEXT = objdump([
    "90000000 <main>:",
    (0x90000000, "3021ffe0", "addik\tr1, r1, -32"),
    (0x90000004, "be060010", "beqid\tr6, 16\t\t// 90000014"),
    (0x90000008, "80000000", "or\tr0, r0, r0"),
    (0x9000000c, "30a00001", "addik\tr5, r0, 1"),
    (0x90000010, "b800000c", "bri\t12\t\t// 9000001c"),
    (0x90000014, "30a00002", "addik\tr5, r0, 2"),
    (0x90000018, "30c00003", "addik\tr6, r0, 3"),
    (0x9000001c, "b60f0008", "rtsd\tr15, 8"),
    (0x90000020, "80000000", "or\tr0, r0, r0"),
])

# Same shape without a delay slot (bnei), plus a register-target conditional
# branch, which has no statically knowable outcome.
MB_TEXT2 = objdump([
    "90000100 <alt>:",
    (0x90000100, "bc23000c", "bnei\tr3, 12\t\t// 9000010c"),
    (0x90000104, "30a00001", "addik\tr5, r0, 1"),
    (0x90000108, "30a00002", "addik\tr5, r0, 2"),
    (0x9000010c, "9c651800", "beq\tr3, r4"),
    (0x90000110, "80000000", "or\tr0, r0, r0"),
    (0x90000114, "b60f0008", "rtsd\tr15, 8"),
    (0x90000118, "80000000", "or\tr0, r0, r0"),
])

X86_TEXT = objdump([
    "0000000000401000 <main>:",
    (0x401000, "48 83 ec 08", "sub    $0x8,%rsp"),
    (0x401004, "74 06", "je     40100c <main+0xc>"),
    (0x401006, "b8 01 00 00 00", "mov    $0x1,%eax"),
    (0x40100b, "c3", "ret"),
    (0x40100c, "ff e0", "jmp    *%rax"),
    (0x40100e, "c3", "ret"),
], fmt="elf64-x86-64")


class TestArchProfiles(unittest.TestCase):
    def test_detect_arch_from_file_format(self):
        self.assertEqual(cfg.detect_arch(MB_TEXT), "microblaze")
        self.assertEqual(cfg.detect_arch(X86_TEXT), "x86_64")

    def test_normalize_arch_aliases(self):
        self.assertEqual(cfg.normalize_arch("microblazeel"), "microblaze")
        self.assertEqual(cfg.normalize_arch("riscv64"), "riscv")
        self.assertEqual(cfg.normalize_arch("qemu-system-ppc64le"), "powerpc")

    def test_unknown_arch_is_unsupported_not_guessed(self):
        profile = cfg.get_profile("vax")
        self.assertFalse(profile.supported)
        self.assertEqual(profile.classify("jbr 4 <foo>"), cfg.OTHER)

    def test_user_profile_from_json(self):
        body = {
            "name": "toycpu", "aliases": ["elf32-toy"],
            "conditional": r"^(bz|bnz)\b", "unconditional": r"^jmp\b",
            "call": r"^bsr\b", "return": r"^rts\b",
            "has_delay_slot": True, "insn_size": 2,
        }
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(body, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(cfg.load_profile_file(f.name), ["toycpu"])
        p = cfg.get_profile("elf32-toy")
        self.assertTrue(p.supported)
        self.assertEqual(p.classify("bz 40 <x>"), cfg.COND)
        self.assertEqual(p.classify("rts"), cfg.RET)
        self.assertTrue(p.delays(cfg.COND, "bz 40 <x>"))

    def test_bad_profile_key_rejected(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"name": "x", "conditional": "^b", "typo": 1}, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        with self.assertRaises(ValueError):
            cfg.load_profile_file(f.name)


class TestBlockSplitting(unittest.TestCase):
    def setUp(self):
        self.graph = cfg.analyze(MB_TEXT, cfg.get_profile("microblaze"))

    def test_block_boundaries(self):
        bounds = [(b.start, b.end) for b in self.graph.blocks]
        self.assertEqual(bounds, [
            (0x90000000, 0x90000008),   # ends with the delay slot, not the branch
            (0x9000000c, 0x90000010),   # fall-through path, ends at bri
            (0x90000014, 0x90000018),   # taken target
            (0x9000001c, 0x90000020),   # delayed return + its delay slot
        ])

    def test_delay_slot_is_inside_the_branch_block(self):
        block = self.graph.block_for(0x90000008)
        self.assertEqual(block.start, 0x90000000)
        self.assertEqual(block.terminator.addr, 0x90000004)

    def test_delay_slot_is_never_a_block_leader(self):
        starts = {b.start for b in self.graph.blocks}
        self.assertNotIn(0x90000008, starts)
        self.assertNotIn(0x90000020, starts)

    def test_terminator_kinds(self):
        kinds = [b.terminator.kind if b.terminator else None
                 for b in self.graph.blocks]
        # The third block ends because the bri TARGET (0x9000001c) is a leader,
        # not because it transfers control -- it simply falls through.
        self.assertEqual(kinds, [cfg.COND, cfg.UNCOND, None, cfg.RET])
        self.assertEqual(self.graph.blocks[0].terminator.addr, 0x90000004)
        self.assertEqual(self.graph.blocks[3].terminator.addr, 0x9000001c)


class TestDelaySlotFallthrough(unittest.TestCase):
    def test_fallthrough_skips_the_delay_slot(self):
        graph = cfg.analyze(MB_TEXT, cfg.get_profile("microblaze"))
        self.assertEqual(len(graph.branch_points), 1)
        bp = graph.branch_points[0]
        self.assertEqual(bp.addr, 0x90000004)
        self.assertEqual(bp.taken, 0x90000014)
        # The whole point: NOT 0x90000008 (the delay slot), which executes on
        # both paths, but the instruction after it.
        self.assertEqual(bp.fallthrough, 0x9000000c)
        self.assertFalse(bp.indirect)

    def test_non_delayed_branch_falls_through_to_next_insn(self):
        graph = cfg.analyze(MB_TEXT2, cfg.get_profile("microblaze"))
        bp = [b for b in graph.branch_points if b.addr == 0x90000100][0]
        self.assertEqual(bp.taken, 0x9000010c)
        self.assertEqual(bp.fallthrough, 0x90000104)   # bnei has no delay slot

    def test_x86_has_no_delay_slots(self):
        graph = cfg.analyze(X86_TEXT, cfg.get_profile("x86_64"))
        bp = graph.branch_points[0]
        self.assertEqual(bp.addr, 0x401004)
        self.assertEqual(bp.taken, 0x40100c)
        # Variable-length instructions: fall-through comes from the address
        # delta, so 0x401006, not 0x401004 + 4.
        self.assertEqual(bp.fallthrough, 0x401006)


class TestIndirectBranches(unittest.TestCase):
    def test_register_target_branch_is_excluded(self):
        graph = cfg.analyze(MB_TEXT2, cfg.get_profile("microblaze"))
        addrs = {bp.addr: bp for bp in graph.branch_points}
        self.assertIn(0x9000010c, addrs)             # still a branch POINT
        self.assertTrue(addrs[0x9000010c].indirect)  # but with no known outcomes
        self.assertIsNone(addrs[0x9000010c].taken)
        self.assertEqual([bp.addr for bp in graph.indirect_branches],
                         [0x9000010c])

    def test_x86_indirect_operand_is_not_mistaken_for_a_target(self):
        p = cfg.get_profile("x86_64")
        # The 0x10 displacement must not be read as a branch target.
        self.assertIsNone(cfg._parse_target("jmp    *0x10(%rax)", 0, p))
        self.assertIsNone(cfg._parse_target(
            "jmp    *0x2f16(%rip)        # 5030 <ptr>", 0, p))
        self.assertEqual(cfg._parse_target("je     4000da <foo+0x1a>", 0, p),
                         0x4000da)

    def test_target_outside_the_disassembly_is_dropped(self):
        text = objdump([
            "90000200 <stub>:",
            (0x90000200, "bc230100", "bnei\tr3, 256\t\t// 90000300"),
            (0x90000204, "b60f0008", "rtsd\tr15, 8"),
            (0x90000208, "80000000", "or\tr0, r0, r0"),
        ])
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        self.assertTrue(graph.branch_points[0].indirect)


class TestMicroBlazeAbsoluteTargets(unittest.TestCase):
    """brai/braid/bralid/brki take ABSOLUTE operands, bri/brid/brlid do not.

    microblaze-opc.h tags each immediate branch INST_NO_OFFSET (:226-229) or
    INST_PC_OFFSET (:223-225, :230-241). Adding the PC to an absolute operand
    manufactures an address, and when that address happens to land on a real
    instruction, build_blocks splits a block there -- a corrupt block map
    produced silently, with the right exit status.
    """

    def setUp(self):
        self.profile = cfg.get_profile("microblaze")

    def target(self, text, pc=0x1000):
        return cfg._parse_target(text, pc, self.profile)

    def test_pc_relative_forms_add_the_pc(self):
        self.assertEqual(self.target("bri 256"), 0x1100)
        self.assertEqual(self.target("brid 256"), 0x1100)
        self.assertEqual(self.target("brlid r15, 256"), 0x1100)
        self.assertEqual(self.target("beqid r6, 16"), 0x1010)
        self.assertEqual(self.target("bnei r3, 12"), 0x100c)
        self.assertEqual(self.target("bri -12"), 0xff4)

    def test_absolute_forms_do_not_add_the_pc(self):
        self.assertEqual(self.target("brai 256"), 0x100)
        self.assertEqual(self.target("braid 256"), 0x100)
        self.assertEqual(self.target("bralid r15, 256"), 0x100)
        self.assertEqual(self.target("brki r16, 8"), 0x8)

    def test_absolute_operand_does_not_inject_a_false_block_leader(self):
        # 'braid 16' at 0x90000004 is absolute: it goes to 0x10, which is not in
        # this dump. Read as PC-relative it would "target" 0x90000014, a real
        # instruction, and split that block in two.
        text = objdump([
            "90000000 <main>:",
            (0x90000000, "3021ffe0", "addik\tr1, r1, -32"),
            (0x90000004, "b8180010", "braid\t16"),
            (0x90000008, "80000000", "or\tr0, r0, r0"),
            (0x9000000c, "30a00001", "addik\tr5, r0, 1"),
            (0x90000010, "30a00002", "addik\tr5, r0, 2"),
            (0x90000014, "30a00003", "addik\tr5, r0, 3"),
            (0x90000018, "b60f0008", "rtsd\tr15, 8"),
            (0x9000001c, "80000000", "or\tr0, r0, r0"),
        ])
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        braid = [i for i in graph.insns if i.mnemonic == "braid"][0]
        self.assertEqual(braid.target, 0x10)
        self.assertEqual([(b.start, b.end) for b in graph.blocks], [
            (0x90000000, 0x90000008),   # ends with braid's delay slot
            (0x9000000c, 0x9000001c),   # NOT split at 0x90000014
        ])

    def test_absolute_target_that_is_real_is_kept(self):
        # Absolute really can name an address in the dump; when it does, it must
        # become a leader, so the fix is not "ignore absolute operands".
        text = objdump([
            "00000000 <main>:",
            (0x00000000, "3021ffe0", "addik\tr1, r1, -32"),
            (0x00000004, "b8180010", "braid\t16"),
            (0x00000008, "80000000", "or\tr0, r0, r0"),
            (0x0000000c, "30a00001", "addik\tr5, r0, 1"),
            (0x00000010, "b60f0008", "rtsd\tr15, 8"),
            (0x00000014, "80000000", "or\tr0, r0, r0"),
        ])
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        braid = [i for i in graph.insns if i.mnemonic == "braid"][0]
        self.assertEqual(braid.target, 0x10)
        self.assertIn(0x10, {b.start for b in graph.blocks})

    def test_absolute_key_is_accepted_in_a_user_profile(self):
        body = {"name": "toyabs", "unconditional": r"^(jr|ja)\b",
                "pcrel_operand": True, "absolute": r"^ja\b"}
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(body, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        cfg.load_profile_file(f.name)
        p = cfg.get_profile("toyabs")
        self.assertEqual(cfg._parse_target("jr 16", 0x100, p), 0x110)
        self.assertEqual(cfg._parse_target("ja 16", 0x100, p), 0x10)


# A STRIPPED binary: GNU objdump prints the branch target as a bare hex number
# and appends " <sym+off>" only when a symbol covers it. Same instructions, same
# targets -- just no symbol table, and no symbol header lines either.
STRIPPED_AARCH64 = objdump([
    (0x4008a0, "1f000871", "cmp\tw0, #0x1"),
    (0x4008a4, "ab00005a", "b.lt\t4008b0"),
    (0x4008a8, "20008052", "mov\tw0, #0x1"),
    (0x4008ac, "c0035fd6", "ret"),
    (0x4008b0, "00008052", "mov\tw0, #0x0"),
    (0x4008b4, "c0035fd6", "ret"),
], fmt="elf64-littleaarch64")


class TestStrippedBinaryTargets(unittest.TestCase):
    """A direct branch stays direct when the symbols are gone.

    Requiring a literal '0x' or a '<sym>' suffix made every branch in a stripped
    ELF parse as indirect, so the whole branch inventory was excluded and the
    denominator silently became zero -- branch coverage reported nothing rather
    than reporting a problem.
    """

    def test_bare_hex_target_is_resolved(self):
        graph = cfg.analyze(STRIPPED_AARCH64, cfg.get_profile("aarch64"))
        self.assertEqual([(bp.addr, bp.mnemonic, bp.taken, bp.fallthrough)
                          for bp in graph.branch_points],
                         [(0x4008a4, "b.lt", 0x4008b0, 0x4008a8)])
        self.assertEqual(graph.indirect_branches, [])

    def test_symbolic_and_stripped_forms_agree(self):
        """The <sym+off> suffix must not change the parsed target."""
        p = cfg.get_profile("aarch64")
        addrs = {0x4008b0}
        self.assertEqual(
            cfg._parse_target("b.lt 4008b0", 0, p, None, addrs),
            cfg._parse_target("b.lt 4008b0 <f+0x20>", 0, p, None, addrs))

    def test_bare_number_that_is_not_an_address_is_refused(self):
        """A bare operand is ambiguous, so it is validated, not trusted."""
        p = cfg.get_profile("aarch64")
        self.assertIsNone(cfg._parse_target("b.lt 12", 0, p, None, {0x4008b0}))
        # ...and with no address set at all there is nothing to validate against.
        self.assertIsNone(cfg._parse_target("b.lt 4008b0", 0, p))

    def test_register_operand_is_not_read_as_a_bare_hex_target(self):
        p = cfg.get_profile("aarch64")
        self.assertIsNone(cfg._parse_target("br x8", 0, p, None, {0x8, 0xb0}))
        self.assertIsNone(cfg._parse_target("blr x8", 0, p, None, {0x8}))

    def test_stripped_x86_jump_still_terminates_its_block(self):
        text = objdump([
            (0x401000, "48 83 ec 08", "sub    $0x8,%rsp"),
            (0x401004, "74 06", "je     40100c"),
            (0x401006, "b8 01 00 00 00", "mov    $0x1,%eax"),
            (0x40100b, "c3", "ret"),
            (0x40100c, "31 c0", "xor    %eax,%eax"),
            (0x40100e, "c3", "ret"),
        ], fmt="elf64-x86-64")
        graph = cfg.analyze(text, cfg.get_profile("x86_64"))
        bp = graph.branch_points[0]
        self.assertEqual((bp.taken, bp.fallthrough), (0x40100c, 0x401006))
        self.assertFalse(bp.indirect)

    def test_microblaze_displacement_is_not_read_as_hex(self):
        """MicroBlaze prints a DECIMAL displacement; bare-hex must not win."""
        p = cfg.get_profile("microblaze")
        # 0x90000010 would be reachable if "16" were read as hex 0x16 + pc.
        self.assertEqual(cfg._parse_target("bri 16", 0x90000000, p, None,
                                           {0x90000010, 0x90000016}),
                         0x90000010)

    def test_microblaze_imm_prefixed_branch_stays_unknown(self):
        """An 'imm' prefix makes the printed operand incomplete: refuse it.

        Falling through to a bare-hex reading would re-derive the same wrong
        number in a different base.
        """
        p = cfg.get_profile("microblaze")
        prev = cfg.Insn(0x90000000, "imm -256", "imm", cfg.OTHER, ".text")
        self.assertIsNone(cfg._parse_target("bri 4660", 0x90000004, p, prev,
                                            {0x1234, 0x90000004}))


class TestEdgeMatching(unittest.TestCase):
    def setUp(self):
        self.graph = cfg.analyze(MB_TEXT, cfg.get_profile("microblaze"))

    def match(self, edges):
        return cfg.match_edges(self.graph, edges)

    def test_delay_slot_source_resolves_the_taken_outcome(self):
        # The plugin records the LAST instruction of the TB, which on MicroBlaze
        # is the delay slot (0x...08), not the branch (0x...04).
        counts, stats = self.match([(0x90000008, 0x90000014, 3)])
        self.assertEqual(counts[0x90000004].taken, 3)
        self.assertEqual(counts[0x90000004].nottaken, 0)
        self.assertTrue(counts[0x90000004].evaluated)
        self.assertEqual(stats["matched"], 1)

    def test_fallthrough_edge_resolves_the_not_taken_outcome(self):
        counts, _ = self.match([(0x90000008, 0x9000000c, 5)])
        self.assertEqual(counts[0x90000004].taken, 0)
        self.assertEqual(counts[0x90000004].nottaken, 5)

    def test_both_outcomes_accumulate(self):
        counts, stats = self.match([(0x90000008, 0x90000014, 2),
                                    (0x90000008, 0x9000000c, 7),
                                    (0x90000008, 0x90000014, 1)])
        self.assertEqual((counts[0x90000004].taken,
                          counts[0x90000004].nottaken), (3, 7))
        self.assertEqual(stats["matched"], 3)

    def test_edge_from_a_non_conditional_block_is_ignored(self):
        # bri's block: a plain unconditional transfer, carries no branch info.
        counts, stats = self.match([(0x90000010, 0x9000001c, 9)])
        self.assertEqual(counts, {})
        self.assertEqual(stats["ignored"], 1)

    def test_short_translation_block_before_the_branch_is_ignored(self):
        # QEMU may end a TB early (page boundary); its source is then BEFORE the
        # branch, so the edge is a fall-through and must not be read as data.
        counts, stats = self.match([(0x90000000, 0x90000004, 4)])
        self.assertEqual(counts, {})
        self.assertEqual(stats["ignored"], 1)

    def test_edge_to_an_unknown_destination_is_unresolved_not_invented(self):
        counts, stats = self.match([(0x90000008, 0xdeadbeef, 1)])
        self.assertEqual(stats["unresolved"], 1)
        self.assertEqual((counts[0x90000004].taken,
                          counts[0x90000004].nottaken), (0, 0))
        self.assertFalse(counts[0x90000004].evaluated)

    def test_edges_without_counts_default_to_one(self):
        counts, _ = self.match([(0x90000008, 0x90000014)])
        self.assertEqual(counts[0x90000004].taken, 1)


if __name__ == "__main__":
    unittest.main()
