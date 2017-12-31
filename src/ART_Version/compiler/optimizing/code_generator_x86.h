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

#ifndef ART_COMPILER_OPTIMIZING_CODE_GENERATOR_X86_H_
#define ART_COMPILER_OPTIMIZING_CODE_GENERATOR_X86_H_

#include "code_generator.h"
#include "nodes.h"
#include "parallel_move_resolver.h"
#include "utils/x86/assembler_x86.h"

namespace art {
namespace x86 {

static constexpr size_t kX86WordSize = 4;

class CodeGeneratorX86;

static constexpr Register kParameterCoreRegisters[] = { ECX, EDX, EBX };
static constexpr RegisterPair kParameterCorePairRegisters[] = { ECX_EDX, EDX_EBX };
static constexpr size_t kParameterCoreRegistersLength = arraysize(kParameterCoreRegisters);

class InvokeDexCallingConvention : public CallingConvention<Register> {
 public:
  InvokeDexCallingConvention()
      : CallingConvention(kParameterCoreRegisters, kParameterCoreRegistersLength) {}

  RegisterPair GetRegisterPairAt(size_t argument_index) {
    DCHECK_LT(argument_index + 1, GetNumberOfRegisters());
    return kParameterCorePairRegisters[argument_index];
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(InvokeDexCallingConvention);
};

class InvokeDexCallingConventionVisitor {
 public:
  InvokeDexCallingConventionVisitor() : gp_index_(0) {}

  Location GetNextLocation(Primitive::Type type);

 private:
  InvokeDexCallingConvention calling_convention;
  uint32_t gp_index_;

  DISALLOW_COPY_AND_ASSIGN(InvokeDexCallingConventionVisitor);
};

class ParallelMoveResolverX86 : public ParallelMoveResolver {
 public:
  ParallelMoveResolverX86(ArenaAllocator* allocator, CodeGeneratorX86* codegen)
      : ParallelMoveResolver(allocator), codegen_(codegen) {}

  virtual void EmitMove(size_t index) OVERRIDE;
  virtual void EmitSwap(size_t index) OVERRIDE;
  virtual void SpillScratch(int reg) OVERRIDE;
  virtual void RestoreScratch(int reg) OVERRIDE;

  X86Assembler* GetAssembler() const;

 private:
  void Exchange(Register reg, int mem);
  void Exchange(int mem1, int mem2);
  void MoveMemoryToMemory(int dst, int src);

  CodeGeneratorX86* const codegen_;

  DISALLOW_COPY_AND_ASSIGN(ParallelMoveResolverX86);
};

class LocationsBuilderX86 : public HGraphVisitor {
 public:
  LocationsBuilderX86(HGraph* graph, CodeGeneratorX86* codegen)
      : HGraphVisitor(graph), codegen_(codegen) {}

#define DECLARE_VISIT_INSTRUCTION(name)     \
  virtual void Visit##name(H##name* instr);

  FOR_EACH_CONCRETE_INSTRUCTION(DECLARE_VISIT_INSTRUCTION)

#undef DECLARE_VISIT_INSTRUCTION

 private:
  CodeGeneratorX86* const codegen_;
  InvokeDexCallingConventionVisitor parameter_visitor_;

  DISALLOW_COPY_AND_ASSIGN(LocationsBuilderX86);
};

class InstructionCodeGeneratorX86 : public HGraphVisitor {
 public:
  InstructionCodeGeneratorX86(HGraph* graph, CodeGeneratorX86* codegen);

#define DECLARE_VISIT_INSTRUCTION(name)     \
  virtual void Visit##name(H##name* instr);

  FOR_EACH_CONCRETE_INSTRUCTION(DECLARE_VISIT_INSTRUCTION)

#undef DECLARE_VISIT_INSTRUCTION

  void LoadCurrentMethod(Register reg);

  X86Assembler* GetAssembler() const { return assembler_; }

 private:
  X86Assembler* const assembler_;
  CodeGeneratorX86* const codegen_;

  DISALLOW_COPY_AND_ASSIGN(InstructionCodeGeneratorX86);
};

class CodeGeneratorX86 : public CodeGenerator {
 public:
  explicit CodeGeneratorX86(HGraph* graph);
  virtual ~CodeGeneratorX86() {}

  virtual void GenerateFrameEntry() OVERRIDE;
  virtual void GenerateFrameExit() OVERRIDE;
  virtual void Bind(Label* label) OVERRIDE;
  virtual void Move(HInstruction* instruction, Location location, HInstruction* move_for) OVERRIDE;

  virtual size_t GetWordSize() const OVERRIDE {
    return kX86WordSize;
  }

  virtual size_t FrameEntrySpillSize() const OVERRIDE;

  virtual HGraphVisitor* GetLocationBuilder() OVERRIDE {
    return &location_builder_;
  }

  virtual HGraphVisitor* GetInstructionVisitor() OVERRIDE {
    return &instruction_visitor_;
  }

  virtual X86Assembler* GetAssembler() OVERRIDE {
    return &assembler_;
  }

  virtual size_t GetNumberOfRegisters() const OVERRIDE;
  virtual void SetupBlockedRegisters(bool* blocked_registers) const OVERRIDE;
  virtual ManagedRegister AllocateFreeRegister(
      Primitive::Type type, bool* blocked_registers) const OVERRIDE;

  virtual Location GetStackLocation(HLoadLocal* load) const OVERRIDE;

  virtual size_t GetNumberOfCoreRegisters() const OVERRIDE {
    return kNumberOfCpuRegisters;
  }

  virtual size_t GetNumberOfFloatingPointRegisters() const OVERRIDE {
    return kNumberOfXmmRegisters;
  }

  virtual void DumpCoreRegister(std::ostream& stream, int reg) const OVERRIDE;
  virtual void DumpFloatingPointRegister(std::ostream& stream, int reg) const OVERRIDE;

  ParallelMoveResolverX86* GetMoveResolver() {
    return &move_resolver_;
  }

  virtual InstructionSet GetInstructionSet() const OVERRIDE {
    return InstructionSet::kX86;
  }

  // Helper method to move a 32bits value between two locations.
  void Move32(Location destination, Location source);
  // Helper method to move a 64bits value between two locations.
  void Move64(Location destination, Location source);

  // Emit a write barrier.
  void MarkGCCard(Register temp, Register card, Register object, Register value);

 private:
  LocationsBuilderX86 location_builder_;
  InstructionCodeGeneratorX86 instruction_visitor_;
  ParallelMoveResolverX86 move_resolver_;
  X86Assembler assembler_;

  DISALLOW_COPY_AND_ASSIGN(CodeGeneratorX86);
};

}  // namespace x86
}  // namespace art

#endif  // ART_COMPILER_OPTIMIZING_CODE_GENERATOR_X86_H_
