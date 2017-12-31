/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "builder.h"
#include "code_generator.h"
#include "dex_file.h"
#include "dex_instruction.h"
#include "nodes.h"
#include "optimizing_unit_test.h"
#include "ssa_liveness_analysis.h"
#include "utils/arena_allocator.h"

#include "gtest/gtest.h"

namespace art {

static void DumpBitVector(BitVector* vector,
                          std::ostream& buffer,
                          size_t count,
                          const char* prefix) {
  buffer << prefix;
  buffer << '(';
  for (size_t i = 0; i < count; ++i) {
    buffer << vector->IsBitSet(i);
  }
  buffer << ")\n";
}

static void TestCode(const uint16_t* data, const char* expected) {
  ArenaPool pool;
  ArenaAllocator allocator(&pool);
  HGraphBuilder builder(&allocator);
  const DexFile::CodeItem* item = reinterpret_cast<const DexFile::CodeItem*>(data);
  HGraph* graph = builder.BuildGraph(*item);
  ASSERT_NE(graph, nullptr);
  graph->BuildDominatorTree();
  graph->TransformToSSA();
  graph->FindNaturalLoops();
  CodeGenerator* codegen = CodeGenerator::Create(&allocator, graph, InstructionSet::kX86);
  SsaLivenessAnalysis liveness(*graph, codegen);
  liveness.Analyze();

  std::ostringstream buffer;
  for (HInsertionOrderIterator it(*graph); !it.Done(); it.Advance()) {
    HBasicBlock* block = it.Current();
    buffer << "Block " << block->GetBlockId() << std::endl;
    size_t ssa_values = liveness.GetNumberOfSsaValues();
    BitVector* live_in = liveness.GetLiveInSet(*block);
    DumpBitVector(live_in, buffer, ssa_values, "  live in: ");
    BitVector* live_out = liveness.GetLiveOutSet(*block);
    DumpBitVector(live_out, buffer, ssa_values, "  live out: ");
    BitVector* kill = liveness.GetKillSet(*block);
    DumpBitVector(kill, buffer, ssa_values, "  kill: ");
  }
  ASSERT_STREQ(expected, buffer.str().c_str());
}

TEST(LivenessTest, CFG1) {
  const char* expected =
    "Block 0\n"
    "  live in: (0)\n"
    "  live out: (0)\n"
    "  kill: (1)\n"
    "Block 1\n"
    "  live in: (0)\n"
    "  live out: (0)\n"
    "  kill: (0)\n"
    "Block 2\n"
    "  live in: (0)\n"
    "  live out: (0)\n"
    "  kill: (0)\n";

  // Constant is not used.
  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::RETURN_VOID);

  TestCode(data, expected);
}

TEST(LivenessTest, CFG2) {
  const char* expected =
    "Block 0\n"
    "  live in: (0)\n"
    "  live out: (1)\n"
    "  kill: (1)\n"
    "Block 1\n"
    "  live in: (1)\n"
    "  live out: (0)\n"
    "  kill: (0)\n"
    "Block 2\n"
    "  live in: (0)\n"
    "  live out: (0)\n"
    "  kill: (0)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::RETURN);

  TestCode(data, expected);
}

TEST(LivenessTest, CFG3) {
  const char* expected =
    "Block 0\n"  // entry block
    "  live in: (000)\n"
    "  live out: (110)\n"
    "  kill: (110)\n"
    "Block 1\n"  // block with add
    "  live in: (110)\n"
    "  live out: (001)\n"
    "  kill: (001)\n"
    "Block 2\n"  // block with return
    "  live in: (001)\n"
    "  live out: (000)\n"
    "  kill: (000)\n"
    "Block 3\n"  // exit block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (000)\n";

  const uint16_t data[] = TWO_REGISTERS_CODE_ITEM(
    Instruction::CONST_4 | 3 << 12 | 0,
    Instruction::CONST_4 | 4 << 12 | 1 << 8,
    Instruction::ADD_INT_2ADDR | 1 << 12,
    Instruction::GOTO | 0x100,
    Instruction::RETURN);

  TestCode(data, expected);
}

TEST(LivenessTest, CFG4) {
  // var a;
  // if (0 == 0) {
  //   a = 5;
  // } else {
  //   a = 4;
  // }
  // return a;
  //
  // Bitsets are made of:
  // (constant0, constant4, constant5, phi)
  const char* expected =
    "Block 0\n"  // entry block
    "  live in: (0000)\n"
    "  live out: (1110)\n"
    "  kill: (1110)\n"
    "Block 1\n"  // block with if
    "  live in: (1110)\n"
    "  live out: (0110)\n"
    "  kill: (0000)\n"
    "Block 2\n"  // else block
    "  live in: (0100)\n"
    "  live out: (0000)\n"
    "  kill: (0000)\n"
    "Block 3\n"  // then block
    "  live in: (0010)\n"
    "  live out: (0000)\n"
    "  kill: (0000)\n"
    "Block 4\n"  // return block
    "  live in: (0000)\n"
    "  live out: (0000)\n"
    "  kill: (0001)\n"
    "Block 5\n"  // exit block
    "  live in: (0000)\n"
    "  live out: (0000)\n"
    "  kill: (0000)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::GOTO | 0x200,
    Instruction::CONST_4 | 5 << 12 | 0,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}

TEST(LivenessTest, CFG5) {
  // var a = 0;
  // if (0 == 0) {
  // } else {
  //   a = 4;
  // }
  // return a;
  //
  // Bitsets are made of:
  // (constant0, constant4, phi)
  const char* expected =
    "Block 0\n"  // entry block
    "  live in: (000)\n"
    "  live out: (110)\n"
    "  kill: (110)\n"
    "Block 1\n"  // block with if
    "  live in: (110)\n"
    "  live out: (110)\n"
    "  kill: (000)\n"
    "Block 2\n"  // else block
    "  live in: (010)\n"
    "  live out: (000)\n"
    "  kill: (000)\n"
    "Block 3\n"  // return block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (001)\n"
    "Block 4\n"  // exit block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (000)\n"
    "Block 5\n"  // block to avoid critical edge. Predecessor is 1, successor is 3.
    "  live in: (100)\n"
    "  live out: (000)\n"
    "  kill: (000)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 3,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}

TEST(LivenessTest, Loop1) {
  // Simple loop with one preheader and one back edge.
  // var a = 0;
  // while (a == a) {
  //   a = 4;
  // }
  // return;
  // Bitsets are made of:
  // (constant0, constant4, phi)
  const char* expected =
    "Block 0\n"  // entry block
    "  live in: (000)\n"
    "  live out: (110)\n"
    "  kill: (110)\n"
    "Block 1\n"  // pre header
    "  live in: (110)\n"
    "  live out: (010)\n"
    "  kill: (000)\n"
    "Block 2\n"  // loop header
    "  live in: (010)\n"
    "  live out: (010)\n"
    "  kill: (001)\n"
    "Block 3\n"  // back edge
    "  live in: (010)\n"
    "  live out: (010)\n"
    "  kill: (000)\n"
    "Block 4\n"  // return block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (000)\n"
    "Block 5\n"  // exit block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (000)\n";


  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::GOTO | 0xFD00,
    Instruction::RETURN_VOID);

  TestCode(data, expected);
}

TEST(LivenessTest, Loop3) {
  // Test that the returned value stays live in a preceding loop.
  // var a = 0;
  // while (a == a) {
  //   a = 4;
  // }
  // return 5;
  // Bitsets are made of:
  // (constant0, constant4, constant5, phi)
  const char* expected =
    "Block 0\n"
    "  live in: (0000)\n"
    "  live out: (1110)\n"
    "  kill: (1110)\n"
    "Block 1\n"
    "  live in: (1110)\n"
    "  live out: (0110)\n"
    "  kill: (0000)\n"
    "Block 2\n"  // loop header
    "  live in: (0110)\n"
    "  live out: (0110)\n"
    "  kill: (0001)\n"
    "Block 3\n"  // back edge
    "  live in: (0110)\n"
    "  live out: (0110)\n"
    "  kill: (0000)\n"
    "Block 4\n"  // return block
    "  live in: (0010)\n"
    "  live out: (0000)\n"
    "  kill: (0000)\n"
    "Block 5\n"  // exit block
    "  live in: (0000)\n"
    "  live out: (0000)\n"
    "  kill: (0000)\n";

  const uint16_t data[] = TWO_REGISTERS_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::GOTO | 0xFD00,
    Instruction::CONST_4 | 5 << 12 | 1 << 8,
    Instruction::RETURN | 1 << 8);

  TestCode(data, expected);
}


TEST(LivenessTest, Loop4) {
  // Make sure we support a preheader of a loop not being the first predecessor
  // in the predecessor list of the header.
  // var a = 0;
  // while (a == a) {
  //   a = 4;
  // }
  // return a;
  // Bitsets are made of:
  // (constant0, constant4, phi)
  const char* expected =
    "Block 0\n"
    "  live in: (000)\n"
    "  live out: (110)\n"
    "  kill: (110)\n"
    "Block 1\n"
    "  live in: (110)\n"
    "  live out: (110)\n"
    "  kill: (000)\n"
    "Block 2\n"  // loop header
    "  live in: (010)\n"
    "  live out: (011)\n"
    "  kill: (001)\n"
    "Block 3\n"  // back edge
    "  live in: (010)\n"
    "  live out: (010)\n"
    "  kill: (000)\n"
    "Block 4\n"  // pre loop header
    "  live in: (110)\n"
    "  live out: (010)\n"
    "  kill: (000)\n"
    "Block 5\n"  // return block
    "  live in: (001)\n"
    "  live out: (000)\n"
    "  kill: (000)\n"
    "Block 6\n"  // exit block
    "  live in: (000)\n"
    "  live out: (000)\n"
    "  kill: (000)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::GOTO | 0x500,
    Instruction::IF_EQ, 5,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::GOTO | 0xFD00,
    Instruction::GOTO | 0xFC00,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}

TEST(LivenessTest, Loop5) {
  // Make sure we create a preheader of a loop when a header originally has two
  // incoming blocks and one back edge.
  // Bitsets are made of:
  // (constant0, constant4, constant5, phi in block 8, phi in block 4)
  const char* expected =
    "Block 0\n"
    "  live in: (00000)\n"
    "  live out: (11100)\n"
    "  kill: (11100)\n"
    "Block 1\n"
    "  live in: (11100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 2\n"
    "  live in: (01000)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 3\n"
    "  live in: (00100)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 4\n"  // loop header
    "  live in: (00000)\n"
    "  live out: (00001)\n"
    "  kill: (00001)\n"
    "Block 5\n"  // back edge
    "  live in: (00001)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 6\n"  // return block
    "  live in: (00001)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 7\n"  // exit block
    "  live in: (00000)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 8\n"  // synthesized pre header
    "  live in: (00000)\n"
    "  live out: (00000)\n"
    "  kill: (00010)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::GOTO | 0x200,
    Instruction::CONST_4 | 5 << 12 | 0,
    Instruction::IF_EQ, 3,
    Instruction::GOTO | 0xFE00,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}

TEST(LivenessTest, Loop6) {
  // Bitsets are made of:
  // (constant0, constant4, constant5, phi in block 2, phi in block 8)
  const char* expected =
    "Block 0\n"
    "  live in: (00000)\n"
    "  live out: (11100)\n"
    "  kill: (11100)\n"
    "Block 1\n"
    "  live in: (11100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 2\n"  // loop header
    "  live in: (01100)\n"
    "  live out: (01110)\n"
    "  kill: (00010)\n"
    "Block 3\n"
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 4\n"  // original back edge
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 5\n"  // original back edge
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 6\n"  // return block
    "  live in: (00010)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 7\n"  // exit block
    "  live in: (00000)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 8\n"  // synthesized back edge
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00001)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 8,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 5 << 12 | 0,
    Instruction::GOTO | 0xFA00,
    Instruction::GOTO | 0xF900,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}


TEST(LivenessTest, Loop7) {
  // Bitsets are made of:
  // (constant0, constant4, constant5, phi in block 2, phi in block 6)
  const char* expected =
    "Block 0\n"
    "  live in: (00000)\n"
    "  live out: (11100)\n"
    "  kill: (11100)\n"
    "Block 1\n"
    "  live in: (11100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 2\n"  // loop header
    "  live in: (01100)\n"
    "  live out: (01110)\n"
    "  kill: (00010)\n"
    "Block 3\n"
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 4\n"  // loop exit
    "  live in: (00100)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 5\n"  // back edge
    "  live in: (01100)\n"
    "  live out: (01100)\n"
    "  kill: (00000)\n"
    "Block 6\n"  // return block
    "  live in: (00000)\n"
    "  live out: (00000)\n"
    "  kill: (00001)\n"
    "Block 7\n"  // exit block
    "  live in: (00000)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n"
    "Block 8\n"  // synthesized block to avoid critical edge.
    "  live in: (00010)\n"
    "  live out: (00000)\n"
    "  kill: (00000)\n";

  const uint16_t data[] = ONE_REGISTER_CODE_ITEM(
    Instruction::CONST_4 | 0 | 0,
    Instruction::IF_EQ, 8,
    Instruction::CONST_4 | 4 << 12 | 0,
    Instruction::IF_EQ, 4,
    Instruction::CONST_4 | 5 << 12 | 0,
    Instruction::GOTO | 0x0200,
    Instruction::GOTO | 0xF900,
    Instruction::RETURN | 0 << 8);

  TestCode(data, expected);
}

}  // namespace art
