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

#include "instruction_set.h"

#include "common_runtime_test.h"

namespace art {

class InstructionSetTest : public CommonRuntimeTest {};

TEST_F(InstructionSetTest, GetInstructionSetFromString) {
  EXPECT_EQ(kArm, GetInstructionSetFromString("arm"));
  EXPECT_EQ(kArm64, GetInstructionSetFromString("arm64"));
  EXPECT_EQ(kX86, GetInstructionSetFromString("x86"));
  EXPECT_EQ(kX86_64, GetInstructionSetFromString("x86_64"));
  EXPECT_EQ(kMips, GetInstructionSetFromString("mips"));
  EXPECT_EQ(kNone, GetInstructionSetFromString("none"));
  EXPECT_EQ(kNone, GetInstructionSetFromString("random-string"));
}

TEST_F(InstructionSetTest, GetInstructionSetString) {
  EXPECT_STREQ("arm", GetInstructionSetString(kArm));
  EXPECT_STREQ("arm", GetInstructionSetString(kThumb2));
  EXPECT_STREQ("arm64", GetInstructionSetString(kArm64));
  EXPECT_STREQ("x86", GetInstructionSetString(kX86));
  EXPECT_STREQ("x86_64", GetInstructionSetString(kX86_64));
  EXPECT_STREQ("mips", GetInstructionSetString(kMips));
  EXPECT_STREQ("none", GetInstructionSetString(kNone));
}

TEST_F(InstructionSetTest, TestRoundTrip) {
  EXPECT_EQ(kRuntimeISA, GetInstructionSetFromString(GetInstructionSetString(kRuntimeISA)));
}

TEST_F(InstructionSetTest, PointerSize) {
  EXPECT_EQ(kPointerSize, GetInstructionSetPointerSize(kRuntimeISA));
}

}  // namespace art
