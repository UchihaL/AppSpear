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

#include "context_x86.h"

#include "mirror/art_method-inl.h"
#include "mirror/object-inl.h"
#include "quick/quick_method_frame_info.h"
#include "stack.h"

namespace art {
namespace x86 {

static constexpr uintptr_t gZero = 0;

void X86Context::Reset() {
  for (size_t  i = 0; i < kNumberOfCpuRegisters; i++) {
    gprs_[i] = nullptr;
  }
  gprs_[ESP] = &esp_;
  // Initialize registers with easy to spot debug values.
  esp_ = X86Context::kBadGprBase + ESP;
  eip_ = X86Context::kBadGprBase + kNumberOfCpuRegisters;
}

void X86Context::FillCalleeSaves(const StackVisitor& fr) {
  mirror::ArtMethod* method = fr.GetMethod();
  const QuickMethodFrameInfo frame_info = method->GetQuickFrameInfo();
  size_t spill_count = POPCOUNT(frame_info.CoreSpillMask());
  DCHECK_EQ(frame_info.FpSpillMask(), 0u);
  if (spill_count > 0) {
    // Lowest number spill is farthest away, walk registers and fill into context.
    int j = 2;  // Offset j to skip return address spill.
    for (int i = 0; i < kNumberOfCpuRegisters; i++) {
      if (((frame_info.CoreSpillMask() >> i) & 1) != 0) {
        gprs_[i] = fr.CalleeSaveAddress(spill_count - j, frame_info.FrameSizeInBytes());
        j++;
      }
    }
  }
}

void X86Context::SmashCallerSaves() {
  // This needs to be 0 because we want a null/zero return value.
  gprs_[EAX] = const_cast<uintptr_t*>(&gZero);
  gprs_[EDX] = const_cast<uintptr_t*>(&gZero);
  gprs_[ECX] = nullptr;
  gprs_[EBX] = nullptr;
}

bool X86Context::SetGPR(uint32_t reg, uintptr_t value) {
  CHECK_LT(reg, static_cast<uint32_t>(kNumberOfCpuRegisters));
  CHECK_NE(gprs_[reg], &gZero);
  if (gprs_[reg] != nullptr) {
    *gprs_[reg] = value;
    return true;
  } else {
    return false;
  }
}

void X86Context::DoLongJump() {
#if defined(__i386__)
  // Array of GPR values, filled from the context backward for the long jump pop. We add a slot at
  // the top for the stack pointer that doesn't get popped in a pop-all.
  volatile uintptr_t gprs[kNumberOfCpuRegisters + 1];
  for (size_t i = 0; i < kNumberOfCpuRegisters; ++i) {
    gprs[kNumberOfCpuRegisters - i - 1] = gprs_[i] != nullptr ? *gprs_[i] : X86Context::kBadGprBase + i;
  }
  // We want to load the stack pointer one slot below so that the ret will pop eip.
  uintptr_t esp = gprs[kNumberOfCpuRegisters - ESP - 1] - kWordSize;
  gprs[kNumberOfCpuRegisters] = esp;
  *(reinterpret_cast<uintptr_t*>(esp)) = eip_;
  __asm__ __volatile__(
      "movl %0, %%esp\n\t"  // ESP points to gprs.
      "popal\n\t"           // Load all registers except ESP and EIP with values in gprs.
      "popl %%esp\n\t"      // Load stack pointer.
      "ret\n\t"             // From higher in the stack pop eip.
      :  // output.
      : "g"(&gprs[0])  // input.
      :);  // clobber.
#else
  UNIMPLEMENTED(FATAL);
#endif
}

}  // namespace x86
}  // namespace art
