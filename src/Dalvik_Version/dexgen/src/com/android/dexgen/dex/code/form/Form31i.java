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

import com.android.dexgen.dex.code.CstInsn;
import com.android.dexgen.dex.code.DalvInsn;
import com.android.dexgen.dex.code.InsnFormat;
import com.android.dexgen.rop.code.RegisterSpecList;
import com.android.dexgen.rop.cst.Constant;
import com.android.dexgen.rop.cst.CstLiteralBits;
import com.android.dexgen.util.AnnotatedOutput;

/**
 * Instruction format {@code 31i}. See the instruction format spec
 * for details.
 */
public final class Form31i extends InsnFormat {
    /** {@code non-null;} unique instance of this class */
    public static final InsnFormat THE_ONE = new Form31i();

    /**
     * Constructs an instance. This class is not publicly
     * instantiable. Use {@link #THE_ONE}.
     */
    private Form31i() {
        // This space intentionally left blank.
    }

    /** {@inheritDoc} */
    @Override
    public String insnArgString(DalvInsn insn) {
        RegisterSpecList regs = insn.getRegisters();
        CstLiteralBits value = (CstLiteralBits) ((CstInsn) insn).getConstant();

        return regs.get(0).regString() + ", " + literalBitsString(value);
    }

    /** {@inheritDoc} */
    @Override
    public String insnCommentString(DalvInsn insn, boolean noteIndices) {
        CstLiteralBits value = (CstLiteralBits) ((CstInsn) insn).getConstant();
        return literalBitsComment(value, 32);
    }

    /** {@inheritDoc} */
    @Override
    public int codeSize() {
        return 3;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isCompatible(DalvInsn insn) {
        RegisterSpecList regs = insn.getRegisters();
        if (!((insn instanceof CstInsn) &&
              (regs.size() == 1) &&
              unsignedFitsInByte(regs.get(0).getReg()))) {
            return false;
        }

        CstInsn ci = (CstInsn) insn;
        Constant cst = ci.getConstant();

        if (!(cst instanceof CstLiteralBits)) {
            return false;
        }

        return ((CstLiteralBits) cst).fitsInInt();
    }

    /** {@inheritDoc} */
    @Override
    public InsnFormat nextUp() {
        return Form51l.THE_ONE;
    }

    /** {@inheritDoc} */
    @Override
    public void writeTo(AnnotatedOutput out, DalvInsn insn) {
        RegisterSpecList regs = insn.getRegisters();
        int value =
            ((CstLiteralBits) ((CstInsn) insn).getConstant()).getIntBits();

        write(out,
              opcodeUnit(insn, regs.get(0).getReg()),
              (short) value,
              (short) (value >> 16));
    }
}
