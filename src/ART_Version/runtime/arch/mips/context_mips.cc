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

#include "context_mips.h"

#include "mirror/art_method-inl.h"
#include "mirror/object-inl.h"
#include "quick/quick_method_frame_info.h"
#include "stack.h"

namespace art {
namespace mips {

static constexpr uint32_t gZero = 0;

void MipsContext::Reset() {
  for (size_t i = 0; i < kNumberOfCoreRegisters; i++) {
    gprs_[i] = nullptr;
  }
  for (size_t i = 0; i < kNumberOfFRegisters; i++) {
    fprs_[i] = nullptr;
  }
  gprs_[SP] = &sp_;
  gprs_[RA] = &ra_;
  // Initialize registers with easy to spot debug values.
  sp_ = MipsContext::kBadGprBase + SP;
  ra_ = MipsContext::kBadGprBase + RA;
}

void MipsContext::FillCalleeSaves(const StackVisitor& fr) {
  mirror::ArtMethod* method = fr.GetMethod();
  const QuickMethodFrameInfo frame_info = method->GetQuickFrameInfo();
  size_t spill_count = POPCOUNT(frame_info.CoreSpillMask());
  size_t fp_spill_count = POPCOUNT(frame_info.FpSpillMask());
  if (spill_count > 0) {
    // Lowest number spill is farthest away, walk registers and fill into context.
    int j = 1;
    for (size_t i = 0; i < kNumberOfCoreRegisters; i++) {
      if (((frame_info.CoreSpillMask() >> i) & 1) != 0) {
        gprs_[i] = fr.CalleeSaveAddress(spill_count - j, frame_info.FrameSizeInBytes());
        j++;
      }
    }
  }
  if (fp_spill_count > 0) {
    // Lowest number spill is farthest away, walk registers and fill into context.
    int j = 1;
    for (size_t i = 0; i < kNumberOfFRegisters; i++) {
      if (((frame_info.FpSpillMask() >> i) & 1) != 0) {
        fprs_[i] = fr.CalleeSaveAddress(spill_count + fp_spill_count - j,
                                        frame_info.FrameSizeInBytes());
        j++;
      }
    }
  }
}

bool MipsContext::SetGPR(uint32_t reg, uintptr_t value) {
  CHECK_LT(reg, static_cast<uint32_t>(kNumberOfCoreRegisters));
  CHECK_NE(gprs_[reg], &gZero);  // Can't overwrite this static value since they are never reset.
  if (gprs_[reg] != nullptr) {
    *gprs_[reg] = value;
    return true;
  } else {
    return false;
  }
}

bool MipsContext::SetFPR(uint32_t reg, uintptr_t value) {
  CHECK_LT(reg, static_cast<uint32_t>(kNumberOfFRegisters));
  CHECK_NE(fprs_[reg], &gZero);  // Can't overwrite this static value since they are never reset.
  if (fprs_[reg] != nullptr) {
    *fprs_[reg] = value;
    return true;
  } else {
    return false;
  }
}

void MipsContext::SmashCallerSaves() {
  // This needs to be 0 because we want a null/zero return value.
  gprs_[V0] = const_cast<uint32_t*>(&gZero);
  gprs_[V1] = const_cast<uint32_t*>(&gZero);
  gprs_[A1] = nullptr;
  gprs_[A2] = nullptr;
  gprs_[A3] = nullptr;
}

extern "C" void art_quick_do_long_jump(uint32_t*, uint32_t*);

void MipsContext::DoLongJump() {
  uintptr_t gprs[kNumberOfCoreRegisters];
  uint32_t fprs[kNumberOfFRegisters];
  for (size_t i = 0; i < kNumberOfCoreRegisters; ++i) {
    gprs[i] = gprs_[i] != nullptr ? *gprs_[i] : MipsContext::kBadGprBase + i;
  }
  for (size_t i = 0; i < kNumberOfFRegisters; ++i) {
    fprs[i] = fprs_[i] != nullptr ? *fprs_[i] : MipsContext::kBadGprBase + i;
  }
  art_quick_do_long_jump(gprs, fprs);
}

}  // namespace mips
}  // namespace art
