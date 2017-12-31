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

#include <stdint.h>

#include "callee_save_frame.h"
#include "common_runtime_test.h"
#include "mirror/art_method-inl.h"
#include "quick/quick_method_frame_info.h"

namespace art {

class QuickTrampolineEntrypointsTest : public CommonRuntimeTest {
 protected:
  static mirror::ArtMethod* CreateCalleeSaveMethod(InstructionSet isa,
                                                   Runtime::CalleeSaveType type)
      NO_THREAD_SAFETY_ANALYSIS {
    Runtime* r = Runtime::Current();

    Thread* t = Thread::Current();
    t->TransitionFromSuspendedToRunnable();  // So we can create callee-save methods.

    r->SetInstructionSet(isa);
    mirror::ArtMethod* save_method = r->CreateCalleeSaveMethod(type);
    r->SetCalleeSaveMethod(save_method, type);

    t->TransitionFromRunnableToSuspended(ThreadState::kNative);  // So we can shut down.

    return save_method;
  }

  static void CheckFrameSize(InstructionSet isa, Runtime::CalleeSaveType type, uint32_t save_size)
      NO_THREAD_SAFETY_ANALYSIS {
    mirror::ArtMethod* save_method = CreateCalleeSaveMethod(isa, type);
    QuickMethodFrameInfo frame_info = save_method->GetQuickFrameInfo();
    EXPECT_EQ(frame_info.FrameSizeInBytes(), save_size) << "Expected and real size differs for "
        << type << " core spills=" << std::hex << frame_info.CoreSpillMask() << " fp spills="
        << frame_info.FpSpillMask() << std::dec << " ISA " << isa;
  }

  static void CheckPCOffset(InstructionSet isa, Runtime::CalleeSaveType type, size_t pc_offset)
      NO_THREAD_SAFETY_ANALYSIS {
    mirror::ArtMethod* save_method = CreateCalleeSaveMethod(isa, type);
    QuickMethodFrameInfo frame_info = save_method->GetQuickFrameInfo();
    EXPECT_EQ(save_method->GetReturnPcOffsetInBytes(), pc_offset) << "Expected and real pc offset"
        " differs for " << type << " core spills=" << std::hex << frame_info.CoreSpillMask() <<
        " fp spills=" << frame_info.FpSpillMask() << std::dec << " ISA " << isa;
  }
};

// Note: these tests are all runtime tests. They let the Runtime create the corresponding ArtMethod
// and check against it. Technically we know and expect certain values, but the Runtime code is
// not constexpr, so we cannot make this compile-time checks (and I want the Runtime code tested).

// This test ensures that kQuickCalleeSaveFrame_RefAndArgs_FrameSize is correct.
TEST_F(QuickTrampolineEntrypointsTest, FrameSize) {
  // We have to use a define here as the callee_save_frame.h functions are constexpr.
#define CHECK_FRAME_SIZE(isa)                                                                     \
  CheckFrameSize(isa, Runtime::kRefsAndArgs, GetCalleeSaveFrameSize(isa, Runtime::kRefsAndArgs)); \
  CheckFrameSize(isa, Runtime::kRefsOnly, GetCalleeSaveFrameSize(isa, Runtime::kRefsOnly));       \
  CheckFrameSize(isa, Runtime::kSaveAll, GetCalleeSaveFrameSize(isa, Runtime::kSaveAll))

  CHECK_FRAME_SIZE(kArm);
  CHECK_FRAME_SIZE(kArm64);
  CHECK_FRAME_SIZE(kMips);
  CHECK_FRAME_SIZE(kX86);
  CHECK_FRAME_SIZE(kX86_64);
}

// This test ensures that GetConstExprPointerSize is correct with respect to
// GetInstructionSetPointerSize.
TEST_F(QuickTrampolineEntrypointsTest, PointerSize) {
  EXPECT_EQ(GetInstructionSetPointerSize(kArm), GetConstExprPointerSize(kArm));
  EXPECT_EQ(GetInstructionSetPointerSize(kArm64), GetConstExprPointerSize(kArm64));
  EXPECT_EQ(GetInstructionSetPointerSize(kMips), GetConstExprPointerSize(kMips));
  EXPECT_EQ(GetInstructionSetPointerSize(kX86), GetConstExprPointerSize(kX86));
  EXPECT_EQ(GetInstructionSetPointerSize(kX86_64), GetConstExprPointerSize(kX86_64));
}

// This test ensures that the constexpr specialization of the return PC offset computation in
// GetCalleeSavePCOffset is correct.
TEST_F(QuickTrampolineEntrypointsTest, ReturnPC) {
  // Ensure that the computation in callee_save_frame.h correct.
  // Note: we can only check against the kRuntimeISA, because the ArtMethod computation uses
  // kPointerSize, which is wrong when the target bitwidth is not the same as the host's.
  CheckPCOffset(kRuntimeISA, Runtime::kRefsAndArgs,
                GetCalleeSavePCOffset(kRuntimeISA, Runtime::kRefsAndArgs));
  CheckPCOffset(kRuntimeISA, Runtime::kRefsOnly,
                GetCalleeSavePCOffset(kRuntimeISA, Runtime::kRefsOnly));
  CheckPCOffset(kRuntimeISA, Runtime::kSaveAll,
                GetCalleeSavePCOffset(kRuntimeISA, Runtime::kSaveAll));
}

}  // namespace art
