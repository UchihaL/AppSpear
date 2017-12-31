/*
 * Copyright (C) 2007 The Android Open Source Project
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

package com.android.dexgen.dex.code.form;

import com.android.dexgen.dex.code.DalvInsn;
import com.android.dexgen.dex.code.HighRegisterPrefix;
import com.android.dexgen.dex.code.InsnFormat;
import com.android.dexgen.dex.code.SimpleInsn;
import com.android.dexgen.rop.code.RegisterSpec;
import com.android.dexgen.rop.code.RegisterSpecList;
import com.android.dexgen.util.AnnotatedOutput;

/**
 * Instruction format {@code 12x}. See the instruction format spec
 * for details.
 */
public final class Form12x extends InsnFormat {
    /** {@code non-null;} unique instance of this class */
    public static final InsnFormat THE_ONE = new Form12x();

    /**
     * Constructs an instance. This class is not publicly
     * instantiable. Use {@link #THE_ONE}.
     */
    private Form12x() {
        // This space intentionally left blank.
    }

    /** {@inheritDoc} */
    @Override
    public String insnArgString(DalvInsn insn) {
        RegisterSpecList regs = insn.getRegisters();
        int sz = regs.size();

        /*
         * The (sz - 2) and (sz - 1) below makes this code work for
         * both the two- and three-register ops. (See "case 3" in
         * isCompatible(), below.)
         */

        return regs.get(sz - 2).regString() + ", " +
            regs.get(sz - 1).regString();
    }

    /** {@inheritDoc} */
    @Override
    public String insnCommentString(DalvInsn insn, boolean noteIndices) {
        // This format has no comment.
        return "";
    }

    /** {@inheritDoc} */
    @Override
    public int codeSize() {
        return 1;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isCompatible(DalvInsn insn) {
        if (!(insn instanceof SimpleInsn)) {
            return false;
        }

        RegisterSpecList regs = insn.getRegisters();
        RegisterSpec rs1;
        RegisterSpec rs2;

        switch (regs.size()) {
            case 2: {
                rs1 = regs.get(0);
                rs2 = regs.get(1);
                break;
            }
            case 3: {
                /*
                 * This format is allowed for ops that are effectively
                 * 3-arg but where the first two args are identical.
                 */
                rs1 = regs.get(1);
                rs2 = regs.get(2);
                if (rs1.getReg() != regs.get(0).getReg()) {
                    return false;
                }
                break;
            }
            default: {
                return false;
            }
        }

        return unsignedFitsInNibble(rs1.getReg()) &&
            unsignedFitsInNibble(rs2.getReg());
    }

    /** {@inheritDoc} */
    @Override
    public InsnFormat nextUp() {
        return Form22x.THE_ONE;
    }

    /** {@inheritDoc} */
    @Override
    public void writeTo(AnnotatedOutput out, DalvInsn insn) {
        RegisterSpecList regs = insn.getRegisters();
        int sz = regs.size();

        /*
         * The (sz - 2) and (sz - 1) below makes this code work for
         * both the two- and three-register ops. (See "case 3" in
         * isCompatible(), above.)
         */

        write(out, opcodeUnit(insn,
                              makeByte(regs.get(sz - 2).getReg(),
                                       regs.get(sz - 1).getReg())));
    }
}
