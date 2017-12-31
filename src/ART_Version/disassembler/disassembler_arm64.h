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

#ifndef ART_DISASSEMBLER_DISASSEMBLER_ARM64_H_
#define ART_DISASSEMBLER_DISASSEMBLER_ARM64_H_

#include "disassembler.h"

#include "a64/decoder-a64.h"
#include "a64/disasm-a64.h"

namespace art {
namespace arm64 {

class DisassemblerArm64 FINAL : public Disassembler {
 public:
  explicit DisassemblerArm64(DisassemblerOptions* options) : Disassembler(options) {
    decoder.AppendVisitor(&disasm);
  }

  size_t Dump(std::ostream& os, const uint8_t* begin) OVERRIDE;
  void Dump(std::ostream& os, const uint8_t* begin, const uint8_t* end) OVERRIDE;

 private:
  vixl::Decoder decoder;
  vixl::Disassembler disasm;

  DISALLOW_COPY_AND_ASSIGN(DisassemblerArm64);
};

}  // namespace arm64
}  // namespace art

#endif  // ART_DISASSEMBLER_DISASSEMBLER_ARM64_H_
