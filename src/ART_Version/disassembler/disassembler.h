/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef ART_DISASSEMBLER_DISASSEMBLER_H_
#define ART_DISASSEMBLER_DISASSEMBLER_H_

#include <stdint.h>

#include <iosfwd>

#include "base/macros.h"
#include "instruction_set.h"

namespace art {

class DisassemblerOptions {
 public:
  // Should the disassembler print absolute or relative addresses.
  const bool absolute_addresses_;

  // Base addess for calculating relative code offsets when absolute_addresses_ is false.
  const uint8_t* const base_address_;

  DisassemblerOptions(bool absolute_addresses, const uint8_t* base_address)
      : absolute_addresses_(absolute_addresses), base_address_(base_address) {}

 private:
  DISALLOW_COPY_AND_ASSIGN(DisassemblerOptions);
};

class Disassembler {
 public:
  // Creates a Disassembler for the given InstructionSet with the
  // non-null DisassemblerOptions which become owned by the
  // Disassembler.
  static Disassembler* Create(InstructionSet instruction_set, DisassemblerOptions* options);

  virtual ~Disassembler() {
    delete disassembler_options_;
  }

  // Dump a single instruction returning the length of that instruction.
  virtual size_t Dump(std::ostream& os, const uint8_t* begin) = 0;
  // Dump instructions within a range.
  virtual void Dump(std::ostream& os, const uint8_t* begin, const uint8_t* end) = 0;

 protected:
  explicit Disassembler(DisassemblerOptions* disassembler_options)
      : disassembler_options_(disassembler_options) {
    CHECK(disassembler_options_ != nullptr);
  }

  std::string FormatInstructionPointer(const uint8_t* begin);

 private:
  DisassemblerOptions* disassembler_options_;
  DISALLOW_COPY_AND_ASSIGN(Disassembler);
};

static inline bool HasBitSet(uint32_t value, uint32_t bit) {
  return (value & (1 << bit)) != 0;
}

}  // namespace art

#endif  // ART_DISASSEMBLER_DISASSEMBLER_H_
