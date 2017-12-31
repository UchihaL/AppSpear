/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef ART_RUNTIME_DEX_INSTRUCTION_INL_H_
#define ART_RUNTIME_DEX_INSTRUCTION_INL_H_

#include "dex_instruction.h"

namespace art {

//------------------------------------------------------------------------------
// VRegA
//------------------------------------------------------------------------------
inline bool Instruction::HasVRegA() const {
  switch (FormatOf(Opcode())) {
    case k10t: return true;
    case k10x: return true;
    case k11n: return true;
    case k11x: return true;
    case k12x: return true;
    case k20t: return true;
    case k21c: return true;
    case k21h: return true;
    case k21s: return true;
    case k21t: return true;
    case k22b: return true;
    case k22c: return true;
    case k22s: return true;
    case k22t: return true;
    case k22x: return true;
    case k23x: return true;
    case k30t: return true;
    case k31c: return true;
    case k31i: return true;
    case k31t: return true;
    case k32x: return true;
    case k35c: return true;
    case k3rc: return true;
    case k51l: return true;
    default: return false;
  }
}

inline int32_t Instruction::VRegA() const {
  switch (FormatOf(Opcode())) {
    case k10t: return VRegA_10t();
    case k10x: return VRegA_10x();
    case k11n: return VRegA_11n();
    case k11x: return VRegA_11x();
    case k12x: return VRegA_12x();
    case k20t: return VRegA_20t();
    case k21c: return VRegA_21c();
    case k21h: return VRegA_21h();
    case k21s: return VRegA_21s();
    case k21t: return VRegA_21t();
    case k22b: return VRegA_22b();
    case k22c: return VRegA_22c();
    case k22s: return VRegA_22s();
    case k22t: return VRegA_22t();
    case k22x: return VRegA_22x();
    case k23x: return VRegA_23x();
    case k30t: return VRegA_30t();
    case k31c: return VRegA_31c();
    case k31i: return VRegA_31i();
    case k31t: return VRegA_31t();
    case k32x: return VRegA_32x();
    case k35c: return VRegA_35c();
    case k3rc: return VRegA_3rc();
    case k51l: return VRegA_51l();
    default:
      LOG(FATAL) << "Tried to access vA of instruction " << Name() << " which has no A operand.";
      exit(EXIT_FAILURE);
  }
}

inline int8_t Instruction::VRegA_10t(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k10t);
  return static_cast<int8_t>(InstAA(inst_data));
}

inline uint8_t Instruction::VRegA_10x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k10x);
  return InstAA(inst_data);
}

inline uint4_t Instruction::VRegA_11n(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k11n);
  return InstA(inst_data);
}

inline uint8_t Instruction::VRegA_11x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k11x);
  return InstAA(inst_data);
}

inline uint4_t Instruction::VRegA_12x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k12x);
  return InstA(inst_data);
}

inline int16_t Instruction::VRegA_20t() const {
  DCHECK_EQ(FormatOf(Opcode()), k20t);
  return static_cast<int16_t>(Fetch16(1));
}

inline uint8_t Instruction::VRegA_21c(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k21c);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_21h(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k21h);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_21s(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k21s);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_21t(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k21t);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_22b(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22b);
  return InstAA(inst_data);
}

inline uint4_t Instruction::VRegA_22c(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22c);
  return InstA(inst_data);
}

inline uint4_t Instruction::VRegA_22s(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22s);
  return InstA(inst_data);
}

inline uint4_t Instruction::VRegA_22t(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22t);
  return InstA(inst_data);
}

inline uint8_t Instruction::VRegA_22x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22x);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_23x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k23x);
  return InstAA(inst_data);
}

inline int32_t Instruction::VRegA_30t() const {
  DCHECK_EQ(FormatOf(Opcode()), k30t);
  return static_cast<int32_t>(Fetch32(1));
}

inline uint8_t Instruction::VRegA_31c(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k31c);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_31i(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k31i);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_31t(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k31t);
  return InstAA(inst_data);
}

inline uint16_t Instruction::VRegA_32x() const {
  DCHECK_EQ(FormatOf(Opcode()), k32x);
  return Fetch16(1);
}

inline uint4_t Instruction::VRegA_35c(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k35c);
  return InstB(inst_data);  // This is labeled A in the spec.
}

inline uint8_t Instruction::VRegA_3rc(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k3rc);
  return InstAA(inst_data);
}

inline uint8_t Instruction::VRegA_51l(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k51l);
  return InstAA(inst_data);
}

//------------------------------------------------------------------------------
// VRegB
//------------------------------------------------------------------------------
inline bool Instruction::HasVRegB() const {
  switch (FormatOf(Opcode())) {
    case k11n: return true;
    case k12x: return true;
    case k21c: return true;
    case k21h: return true;
    case k21s: return true;
    case k21t: return true;
    case k22b: return true;
    case k22c: return true;
    case k22s: return true;
    case k22t: return true;
    case k22x: return true;
    case k23x: return true;
    case k31c: return true;
    case k31i: return true;
    case k31t: return true;
    case k32x: return true;
    case k35c: return true;
    case k3rc: return true;
    case k51l: return true;
    default: return false;
  }
}

inline bool Instruction::HasWideVRegB() const {
  return FormatOf(Opcode()) == k51l;
}

inline int32_t Instruction::VRegB() const {
  switch (FormatOf(Opcode())) {
    case k11n: return VRegB_11n();
    case k12x: return VRegB_12x();
    case k21c: return VRegB_21c();
    case k21h: return VRegB_21h();
    case k21s: return VRegB_21s();
    case k21t: return VRegB_21t();
    case k22b: return VRegB_22b();
    case k22c: return VRegB_22c();
    case k22s: return VRegB_22s();
    case k22t: return VRegB_22t();
    case k22x: return VRegB_22x();
    case k23x: return VRegB_23x();
    case k31c: return VRegB_31c();
    case k31i: return VRegB_31i();
    case k31t: return VRegB_31t();
    case k32x: return VRegB_32x();
    case k35c: return VRegB_35c();
    case k3rc: return VRegB_3rc();
    case k51l: return VRegB_51l();
    default:
      LOG(FATAL) << "Tried to access vB of instruction " << Name() << " which has no B operand.";
      exit(EXIT_FAILURE);
  }
}

inline uint64_t Instruction::WideVRegB() const {
  return VRegB_51l();
}

inline int4_t Instruction::VRegB_11n(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k11n);
  return static_cast<int4_t>((InstB(inst_data) << 28) >> 28);
}

inline uint4_t Instruction::VRegB_12x(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k12x);
  return InstB(inst_data);
}

inline uint16_t Instruction::VRegB_21c() const {
  DCHECK_EQ(FormatOf(Opcode()), k21c);
  return Fetch16(1);
}

inline uint16_t Instruction::VRegB_21h() const {
  DCHECK_EQ(FormatOf(Opcode()), k21h);
  return Fetch16(1);
}

inline int16_t Instruction::VRegB_21s() const {
  DCHECK_EQ(FormatOf(Opcode()), k21s);
  return static_cast<int16_t>(Fetch16(1));
}

inline int16_t Instruction::VRegB_21t() const {
  DCHECK_EQ(FormatOf(Opcode()), k21t);
  return static_cast<int16_t>(Fetch16(1));
}

inline uint8_t Instruction::VRegB_22b() const {
  DCHECK_EQ(FormatOf(Opcode()), k22b);
  return static_cast<uint8_t>(Fetch16(1) & 0xff);
}

inline uint4_t Instruction::VRegB_22c(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22c);
  return InstB(inst_data);
}

inline uint4_t Instruction::VRegB_22s(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22s);
  return InstB(inst_data);
}

inline uint4_t Instruction::VRegB_22t(uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k22t);
  return InstB(inst_data);
}

inline uint16_t Instruction::VRegB_22x() const {
  DCHECK_EQ(FormatOf(Opcode()), k22x);
  return Fetch16(1);
}

inline uint8_t Instruction::VRegB_23x() const {
  DCHECK_EQ(FormatOf(Opcode()), k23x);
  return static_cast<uint8_t>(Fetch16(1) & 0xff);
}

inline uint32_t Instruction::VRegB_31c() const {
  DCHECK_EQ(FormatOf(Opcode()), k31c);
  return Fetch32(1);
}

inline int32_t Instruction::VRegB_31i() const {
  DCHECK_EQ(FormatOf(Opcode()), k31i);
  return static_cast<int32_t>(Fetch32(1));
}

inline int32_t Instruction::VRegB_31t() const {
  DCHECK_EQ(FormatOf(Opcode()), k31t);
  return static_cast<int32_t>(Fetch32(1));
}

inline uint16_t Instruction::VRegB_32x() const {
  DCHECK_EQ(FormatOf(Opcode()), k32x);
  return Fetch16(2);
}

inline uint16_t Instruction::VRegB_35c() const {
  DCHECK_EQ(FormatOf(Opcode()), k35c);
  return Fetch16(1);
}

inline uint16_t Instruction::VRegB_3rc() const {
  DCHECK_EQ(FormatOf(Opcode()), k3rc);
  return Fetch16(1);
}

inline uint64_t Instruction::VRegB_51l() const {
  DCHECK_EQ(FormatOf(Opcode()), k51l);
  uint64_t vB_wide = Fetch32(1) | ((uint64_t) Fetch32(3) << 32);
  return vB_wide;
}

//------------------------------------------------------------------------------
// VRegC
//------------------------------------------------------------------------------
inline bool Instruction::HasVRegC() const {
  switch (FormatOf(Opcode())) {
    case k22b: return true;
    case k22c: return true;
    case k22s: return true;
    case k22t: return true;
    case k23x: return true;
    case k35c: return true;
    case k3rc: return true;
    default: return false;
  }
}

inline int32_t Instruction::VRegC() const {
  switch (FormatOf(Opcode())) {
    case k22b: return VRegC_22b();
    case k22c: return VRegC_22c();
    case k22s: return VRegC_22s();
    case k22t: return VRegC_22t();
    case k23x: return VRegC_23x();
    case k35c: return VRegC_35c();
    case k3rc: return VRegC_3rc();
    default:
      LOG(FATAL) << "Tried to access vC of instruction " << Name() << " which has no C operand.";
      exit(EXIT_FAILURE);
  }
}

inline int8_t Instruction::VRegC_22b() const {
  DCHECK_EQ(FormatOf(Opcode()), k22b);
  return static_cast<int8_t>(Fetch16(1) >> 8);
}

inline uint16_t Instruction::VRegC_22c() const {
  DCHECK_EQ(FormatOf(Opcode()), k22c);
  return Fetch16(1);
}

inline int16_t Instruction::VRegC_22s() const {
  DCHECK_EQ(FormatOf(Opcode()), k22s);
  return static_cast<int16_t>(Fetch16(1));
}

inline int16_t Instruction::VRegC_22t() const {
  DCHECK_EQ(FormatOf(Opcode()), k22t);
  return static_cast<int16_t>(Fetch16(1));
}

inline uint8_t Instruction::VRegC_23x() const {
  DCHECK_EQ(FormatOf(Opcode()), k23x);
  return static_cast<uint8_t>(Fetch16(1) >> 8);
}

inline uint4_t Instruction::VRegC_35c() const {
  DCHECK_EQ(FormatOf(Opcode()), k35c);
  return static_cast<uint4_t>(Fetch16(2) & 0x0f);
}

inline uint16_t Instruction::VRegC_3rc() const {
  DCHECK_EQ(FormatOf(Opcode()), k3rc);
  return Fetch16(2);
}

inline bool Instruction::HasVarArgs() const {
  return FormatOf(Opcode()) == k35c;
}

inline void Instruction::GetVarArgs(uint32_t arg[5], uint16_t inst_data) const {
  DCHECK_EQ(FormatOf(Opcode()), k35c);

  /*
   * Note that the fields mentioned in the spec don't appear in
   * their "usual" positions here compared to most formats. This
   * was done so that the field names for the argument count and
   * reference index match between this format and the corresponding
   * range formats (3rc and friends).
   *
   * Bottom line: The argument count is always in vA, and the
   * method constant (or equivalent) is always in vB.
   */
  uint16_t regList = Fetch16(2);
  uint4_t count = InstB(inst_data);  // This is labeled A in the spec.
  DCHECK_LE(count, 5U) << "Invalid arg count in 35c (" << count << ")";

  /*
   * Copy the argument registers into the arg[] array, and
   * also copy the first argument (if any) into vC. (The
   * DecodedInstruction structure doesn't have separate
   * fields for {vD, vE, vF, vG}, so there's no need to make
   * copies of those.) Note that cases 5..2 fall through.
   */
  switch (count) {
    case 5: arg[4] = InstA(inst_data);
    case 4: arg[3] = (regList >> 12) & 0x0f;
    case 3: arg[2] = (regList >> 8) & 0x0f;
    case 2: arg[1] = (regList >> 4) & 0x0f;
    case 1: arg[0] = regList & 0x0f; break;
    default:  // case 0
      break;  // Valid, but no need to do anything.
  }
}

}  // namespace art

#endif  // ART_RUNTIME_DEX_INSTRUCTION_INL_H_
