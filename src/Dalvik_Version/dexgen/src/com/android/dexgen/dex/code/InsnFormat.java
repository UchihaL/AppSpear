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

package com.android.dexgen.dex.code;

import com.android.dexgen.rop.code.RegisterSpecList;
import com.android.dexgen.rop.cst.Constant;
import com.android.dexgen.rop.cst.CstInteger;
import com.android.dexgen.rop.cst.CstKnownNull;
import com.android.dexgen.rop.cst.CstLiteral64;
import com.android.dexgen.rop.cst.CstLiteralBits;
import com.android.dexgen.util.AnnotatedOutput;
import com.android.dexgen.util.Hex;

/**
 * Base class for all instruction format handlers. Instruction format
 * handlers know how to translate {@link DalvInsn} instances into
 * streams of code words, as well as human-oriented listing strings
 * representing such translations.
 */
public abstract class InsnFormat {
    /**
     * Returns the string form, suitable for inclusion in a listing
     * dump, of the given instruction. The instruction must be of this
     * instance's format for proper operation.
     *
     * @param insn {@code non-null;} the instruction
     * @param noteIndices whether to include an explicit notation of
     * constant pool indices
     * @return {@code non-null;} the string form
     */
    public final String listingString(DalvInsn insn, boolean noteIndices) {
        String op = insn.getOpcode().getName();
        String arg = insnArgString(insn);
        String comment = insnCommentString(insn, noteIndices);
        StringBuilder sb = new StringBuilder(100);

        sb.append(op);

        if (arg.length() != 0) {
            sb.append(' ');
            sb.append(arg);
        }

        if (comment.length() != 0) {
            sb.append(" // ");
            sb.append(comment);
        }

        return sb.toString();
    }

    /**
     * Returns the string form of the arguments to the given instruction.
     * The instruction must be of this instance's format. If the instruction
     * has no arguments, then the result should be {@code ""}, not
     * {@code null}.
     *
     * <p>Subclasses must override this method.</p>
     *
     * @param insn {@code non-null;} the instruction
     * @return {@code non-null;} the string form
     */
    public abstract String insnArgString(DalvInsn insn);

    /**
     * Returns the associated comment for the given instruction, if any.
     * The instruction must be of this instance's format. If the instruction
     * has no comment, then the result should be {@code ""}, not
     * {@code null}.
     *
     * <p>Subclasses must override this method.</p>
     *
     * @param insn {@code non-null;} the instruction
     * @param noteIndices whether to include an explicit notation of
     * constant pool indices
     * @return {@code non-null;} the string form
     */
    public abstract String insnCommentString(DalvInsn insn,
            boolean noteIndices);

    /**
     * Gets the code size of instructions that use this format. The
     * size is a number of 16-bit code units, not bytes. This should
     * throw an exception if this format is of variable size.
     *
     * @return {@code >= 0;} the instruction length in 16-bit code units
     */
    public abstract int codeSize();

    /**
     * Returns whether or not the given instruction's arguments will
     * fit in this instance's format. This includes such things as
     * counting register arguments, checking register ranges, and
     * making sure that additional arguments are of appropriate types
     * and are in-range. If this format has a branch target but the
     * instruction's branch offset is unknown, this method will simply
     * not check the offset.
     *
     * <p>Subclasses must override this method.</p>
     *
     * @param insn {@code non-null;} the instruction to check
     * @return {@code true} iff the instruction's arguments are
     * appropriate for this instance, or {@code false} if not
     */
    public abstract boolean isCompatible(DalvInsn insn);

    /**
     * Returns whether or not the given instruction's branch offset will
     * fit in this instance's format. This always returns {@code false}
     * for formats that don't include a branch offset.
     *
     * <p>The default implementation of this method always returns
     * {@code false}. Subclasses must override this method if they
     * include branch offsets.</p>
     *
     * @param insn {@code non-null;} the instruction to check
     * @return {@code true} iff the instruction's branch offset is
     * appropriate for this instance, or {@code false} if not
     */
    public boolean branchFits(TargetInsn insn) {
        return false;
    }

    /**
     * Returns the next instruction format to try to match an instruction
     * with, presuming that this instance isn't compatible, if any.
     *
     * <p>Subclasses must override this method.</p>
     *
     * @return {@code null-ok;} the next format to try, or {@code null} if
     * there are no suitable alternatives
     */
    public abstract InsnFormat nextUp();

    /**
     * Writes the code units for the given instruction to the given
     * output destination. The instruction must be of this instance's format.
     *
     * <p>Subclasses must override this method.</p>
     *
     * @param out {@code non-null;} the output destination to write to
     * @param insn {@code non-null;} the instruction to write
     */
    public abstract void writeTo(AnnotatedOutput out, DalvInsn insn);

    /**
     * Helper method to return a register list string.
     *
     * @param list {@code non-null;} the list of registers
     * @return {@code non-null;} the string form
     */
    protected static String regListString(RegisterSpecList list) {
        int sz = list.size();
        StringBuffer sb = new StringBuffer(sz * 5 + 2);

        sb.append('{');

        for (int i = 0; i < sz; i++) {
            if (i != 0) {
                sb.append(", ");
            }
            sb.append(list.get(i).regString());
        }

        sb.append('}');

        return sb.toString();
    }

    /**
     * Helper method to return a literal bits argument string.
     *
     * @param value the value
     * @return {@code non-null;} the string form
     */
    protected static String literalBitsString(CstLiteralBits value) {
        StringBuffer sb = new StringBuffer(100);

        sb.append('#');

        if (value instanceof CstKnownNull) {
            sb.append("null");
        } else {
            sb.append(value.typeName());
            sb.append(' ');
            sb.append(value.toHuman());
        }

        return sb.toString();
    }

    /**
     * Helper method to return a literal bits comment string.
     *
     * @param value the value
     * @param width the width of the constant, in bits (used for displaying
     * the uninterpreted bits; one of: {@code 4 8 16 32 64}
     * @return {@code non-null;} the comment
     */
    protected static String literalBitsComment(CstLiteralBits value,
            int width) {
        StringBuffer sb = new StringBuffer(20);

        sb.append("#");

        long bits;

        if (value instanceof CstLiteral64) {
            bits = ((CstLiteral64) value).getLongBits();
        } else {
            bits = value.getIntBits();
        }

        switch (width) {
            case 4:  sb.append(Hex.uNibble((int) bits)); break;
            case 8:  sb.append(Hex.u1((int) bits));      break;
            case 16: sb.append(Hex.u2((int) bits));      break;
            case 32: sb.append(Hex.u4((int) bits));      break;
            case 64: sb.append(Hex.u8(bits));            break;
            default: {
                throw new RuntimeException("shouldn't happen");
            }
        }

        return sb.toString();
    }

    /**
     * Helper method to return a branch address string.
     *
     * @param insn {@code non-null;} the instruction in question
     * @return {@code non-null;} the string form of the instruction's branch target
     */
    protected static String branchString(DalvInsn insn) {
        TargetInsn ti = (TargetInsn) insn;
        int address = ti.getTargetAddress();

        return (address == (char) address) ? Hex.u2(address) : Hex.u4(address);
    }

    /**
     * Helper method to return the comment for a branch.
     *
     * @param insn {@code non-null;} the instruction in question
     * @return {@code non-null;} the comment
     */
    protected static String branchComment(DalvInsn insn) {
        TargetInsn ti = (TargetInsn) insn;
        int offset = ti.getTargetOffset();

        return (offset == (short) offset) ? Hex.s2(offset) : Hex.s4(offset);
    }

    /**
     * Helper method to return a constant string.
     *
     * @param insn {@code non-null;} a constant-bearing instruction
     * @return {@code non-null;} the string form of the contained constant
     */
    protected static String cstString(DalvInsn insn) {
        CstInsn ci = (CstInsn) insn;
        Constant cst = ci.getConstant();

        return cst.toHuman();
    }

    /**
     * Helper method to return an instruction comment for a constant.
     *
     * @param insn {@code non-null;} a constant-bearing instruction
     * @return {@code non-null;} comment string representing the constant
     */
    protected static String cstComment(DalvInsn insn) {
        CstInsn ci = (CstInsn) insn;

        if (! ci.hasIndex()) {
            return "";
        }

        StringBuilder sb = new StringBuilder(20);
        int index = ci.getIndex();

        sb.append(ci.getConstant().typeName());
        sb.append('@');

        if (index < 65536) {
            sb.append(Hex.u2(index));
        } else {
            sb.append(Hex.u4(index));
        }

        return sb.toString();
    }

    /**
     * Helper method to determine if a signed int value fits in a nibble.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range -8..+7
     */
    protected static boolean signedFitsInNibble(int value) {
        return (value >= -8) && (value <= 7);
    }

    /**
     * Helper method to determine if an unsigned int value fits in a nibble.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range 0..0xf
     */
    protected static boolean unsignedFitsInNibble(int value) {
        return value == (value & 0xf);
    }

    /**
     * Helper method to determine if a signed int value fits in a byte.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range -0x80..+0x7f
     */
    protected static boolean signedFitsInByte(int value) {
        return (byte) value == value;
    }

    /**
     * Helper method to determine if an unsigned int value fits in a byte.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range 0..0xff
     */
    protected static boolean unsignedFitsInByte(int value) {
        return value == (value & 0xff);
    }

    /**
     * Helper method to determine if a signed int value fits in a short.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range -0x8000..+0x7fff
     */
    protected static boolean signedFitsInShort(int value) {
        return (short) value == value;
    }

    /**
     * Helper method to determine if an unsigned int value fits in a short.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range 0..0xffff
     */
    protected static boolean unsignedFitsInShort(int value) {
        return value == (value & 0xffff);
    }

    /**
     * Helper method to determine if a signed int value fits in three bytes.
     *
     * @param value the value in question
     * @return {@code true} iff it's in the range -0x800000..+0x7fffff
     */
    protected static boolean signedFitsIn3Bytes(int value) {
        return value == ((value << 8) >> 8);
    }

    /**
     * Helper method to extract the callout-argument index from an
     * appropriate instruction.
     *
     * @param insn {@code non-null;} the instruction
     * @return {@code >= 0;} the callout argument index
     */
    protected static int argIndex(DalvInsn insn) {
        int arg = ((CstInteger) ((CstInsn) insn).getConstant()).getValue();

        if (arg < 0) {
            throw new IllegalArgumentException("bogus insn");
        }

        return arg;
    }

    /**
     * Helper method to combine an opcode and a second byte of data into
     * the appropriate form for emitting into a code buffer.
     *
     * @param insn {@code non-null;} the instruction containing the opcode
     * @param arg {@code 0..255;} arbitrary other byte value
     * @return combined value
     */
    protected static short opcodeUnit(DalvInsn insn, int arg) {
        if ((arg & 0xff) != arg) {
            throw new IllegalArgumentException("arg out of range 0..255");
        }

        int opcode = insn.getOpcode().getOpcode();

        if ((opcode & 0xff) != opcode) {
            throw new IllegalArgumentException("opcode out of range 0..255");
        }

        return (short) (opcode | (arg << 8));
    }

    /**
     * Helper method to combine two bytes into a code unit.
     *
     * @param low {@code 0..255;} low byte
     * @param high {@code 0..255;} high byte
     * @return combined value
     */
    protected static short codeUnit(int low, int high) {
        if ((low & 0xff) != low) {
            throw new IllegalArgumentException("low out of range 0..255");
        }

        if ((high & 0xff) != high) {
            throw new IllegalArgumentException("high out of range 0..255");
        }

        return (short) (low | (high << 8));
    }

    /**
     * Helper method to combine four nibbles into a code unit.
     *
     * @param n0 {@code 0..15;} low nibble
     * @param n1 {@code 0..15;} medium-low nibble
     * @param n2 {@code 0..15;} medium-high nibble
     * @param n3 {@code 0..15;} high nibble
     * @return combined value
     */
    protected static short codeUnit(int n0, int n1, int n2, int n3) {
        if ((n0 & 0xf) != n0) {
            throw new IllegalArgumentException("n0 out of range 0..15");
        }

        if ((n1 & 0xf) != n1) {
            throw new IllegalArgumentException("n1 out of range 0..15");
        }

        if ((n2 & 0xf) != n2) {
            throw new IllegalArgumentException("n2 out of range 0..15");
        }

        if ((n3 & 0xf) != n3) {
            throw new IllegalArgumentException("n3 out of range 0..15");
        }

        return (short) (n0 | (n1 << 4) | (n2 << 8) | (n3 << 12));
    }

    /**
     * Helper method to combine two nibbles into a byte.
     *
     * @param low {@code 0..15;} low nibble
     * @param high {@code 0..15;} high nibble
     * @return {@code 0..255;} combined value
     */
    protected static int makeByte(int low, int high) {
        if ((low & 0xf) != low) {
            throw new IllegalArgumentException("low out of range 0..15");
        }

        if ((high & 0xf) != high) {
            throw new IllegalArgumentException("high out of range 0..15");
        }

        return low | (high << 4);
    }

    /**
     * Writes one code unit to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0) {
        out.writeShort(c0);
    }

    /**
     * Writes two code units to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     * @param c1 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0, short c1) {
        out.writeShort(c0);
        out.writeShort(c1);
    }

    /**
     * Writes three code units to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     * @param c1 code unit to write
     * @param c2 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0, short c1,
                                short c2) {
        out.writeShort(c0);
        out.writeShort(c1);
        out.writeShort(c2);
    }

    /**
     * Writes four code units to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     * @param c1 code unit to write
     * @param c2 code unit to write
     * @param c3 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0, short c1,
                                short c2, short c3) {
        out.writeShort(c0);
        out.writeShort(c1);
        out.writeShort(c2);
        out.writeShort(c3);
    }

    /**
     * Writes five code units to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     * @param c1 code unit to write
     * @param c2 code unit to write
     * @param c3 code unit to write
     * @param c4 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0, short c1,
                                short c2, short c3, short c4) {
        out.writeShort(c0);
        out.writeShort(c1);
        out.writeShort(c2);
        out.writeShort(c3);
        out.writeShort(c4);
    }

    /**
     * Writes six code units to the given output destination.
     *
     * @param out {@code non-null;} where to write to
     * @param c0 code unit to write
     * @param c1 code unit to write
     * @param c2 code unit to write
     * @param c3 code unit to write
     * @param c4 code unit to write
     * @param c5 code unit to write
     */
    protected static void write(AnnotatedOutput out, short c0, short c1,
                                short c2, short c3, short c4, short c5) {
        out.writeShort(c0);
        out.writeShort(c1);
        out.writeShort(c2);
        out.writeShort(c3);
        out.writeShort(c4);
        out.writeShort(c5);
    }
}
