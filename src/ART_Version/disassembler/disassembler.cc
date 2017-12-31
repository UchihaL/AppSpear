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

#include "disassembler.h"

#include <iostream>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "disassembler_arm.h"
#include "disassembler_arm64.h"
#include "disassembler_mips.h"
#include "disassembler_x86.h"

namespace art {

Disassembler* Disassembler::Create(InstructionSet instruction_set, DisassemblerOptions* options) {
  if (instruction_set == kArm || instruction_set == kThumb2) {
    return new arm::DisassemblerArm(options);
  } else if (instruction_set == kArm64) {
    return new arm64::DisassemblerArm64(options);
  } else if (instruction_set == kMips) {
    return new mips::DisassemblerMips(options);
  } else if (instruction_set == kX86) {
    return new x86::DisassemblerX86(options, false);
  } else if (instruction_set == kX86_64) {
    return new x86::DisassemblerX86(options, true);
  } else {
    UNIMPLEMENTED(FATAL) << "no disassembler for " << instruction_set;
    return NULL;
  }
}

std::string Disassembler::FormatInstructionPointer(const uint8_t* begin) {
  if (disassembler_options_->absolute_addresses_) {
    return StringPrintf("%p", begin);
  } else {
    size_t offset = begin - disassembler_options_->base_address_;
    return StringPrintf("0x%08zx", offset);
  }
}

}  // namespace art
