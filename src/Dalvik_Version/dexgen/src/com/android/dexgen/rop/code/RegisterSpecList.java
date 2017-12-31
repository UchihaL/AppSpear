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

package com.android.dexgen.rop.code;

import com.android.dexgen.rop.type.Type;
import com.android.dexgen.rop.type.TypeList;
import com.android.dexgen.util.FixedSizeList;

/**
 * List of {@link RegisterSpec} instances.
 */
public final class RegisterSpecList
        extends FixedSizeList implements TypeList {
    /** {@code non-null;} no-element instance */
    public static final RegisterSpecList EMPTY = new RegisterSpecList(0);

    /**
     * Makes a single-element instance.
     *
     * @param spec {@code non-null;} the element
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public static RegisterSpecList make(RegisterSpec spec) {
        RegisterSpecList result = new RegisterSpecList(1);
        result.set(0, spec);
        return result;
    }

    /**
     * Makes a two-element instance.
     *
     * @param spec0 {@code non-null;} the first element
     * @param spec1 {@code non-null;} the second element
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public static RegisterSpecList make(RegisterSpec spec0,
                                        RegisterSpec spec1) {
        RegisterSpecList result = new RegisterSpecList(2);
        result.set(0, spec0);
        result.set(1, spec1);
        return result;
    }

    /**
     * Makes a three-element instance.
     *
     * @param spec0 {@code non-null;} the first element
     * @param spec1 {@code non-null;} the second element
     * @param spec2 {@code non-null;} the third element
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public static RegisterSpecList make(RegisterSpec spec0, RegisterSpec spec1,
                                        RegisterSpec spec2) {
        RegisterSpecList result = new RegisterSpecList(3);
        result.set(0, spec0);
        result.set(1, spec1);
        result.set(2, spec2);
        return result;
    }

    /**
     * Makes a four-element instance.
     *
     * @param spec0 {@code non-null;} the first element
     * @param spec1 {@code non-null;} the second element
     * @param spec2 {@code non-null;} the third element
     * @param spec3 {@code non-null;} the fourth element
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public static RegisterSpecList make(RegisterSpec spec0, RegisterSpec spec1,
                                        RegisterSpec spec2,
                                        RegisterSpec spec3) {
        RegisterSpecList result = new RegisterSpecList(4);
        result.set(0, spec0);
        result.set(1, spec1);
        result.set(2, spec2);
        result.set(3, spec3);
        return result;
    }

    /**
     * Constructs an instance. All indices initially contain {@code null}.
     *
     * @param size the size of the list
     */
    public RegisterSpecList(int size) {
        super(size);
    }

    /** {@inheritDoc} */
    public Type getType(int n) {
        return get(n).getType().getType();
    }

    /** {@inheritDoc} */
    public int getWordCount() {
        int sz = size();
        int result = 0;

        for (int i = 0; i < sz; i++) {
            result += getType(i).getCategory();
        }

        return result;
    }

    /** {@inheritDoc} */
    public TypeList withAddedType(Type type) {
        throw new UnsupportedOperationException("unsupported");
    }

    /**
     * Gets the indicated element. It is an error to call this with the
     * index for an element which was never set; if you do that, this
     * will throw {@code NullPointerException}.
     *
     * @param n {@code >= 0, < size();} which element
     * @return {@code non-null;} the indicated element
     */
    public RegisterSpec get(int n) {
        return (RegisterSpec) get0(n);
    }

    /**
     * Returns a RegisterSpec in this list that uses the specified register,
     * or null if there is none in this list.
     * @param reg Register to find
     * @return RegisterSpec that uses argument or null.
     */
    public RegisterSpec specForRegister(int reg) {
        int sz = size();
        for (int i = 0; i < sz; i++) {
            RegisterSpec rs;

            rs = get(i);

            if (rs.getReg() == reg) {
                return rs;
            }
        }

        return null;
    }

    /**
     * Returns the index of a RegisterSpec in this list that uses the specified
     * register, or -1 if none in this list uses the register.
     * @param reg Register to find
     * @return index of RegisterSpec or -1
     */
    public int indexOfRegister(int reg) {
        int sz = size();
        for (int i = 0; i < sz; i++) {
            RegisterSpec rs;

            rs = get(i);

            if (rs.getReg() == reg) {
                return i;
            }
        }

        return -1;
    }

    /**
     * Sets the element at the given index.
     *
     * @param n {@code >= 0, < size();} which element
     * @param spec {@code non-null;} the value to store
     */
    public void set(int n, RegisterSpec spec) {
        set0(n, spec);
    }

    /**
     * Gets the minimum required register count implied by this
     * instance. This is equal to the highest register number referred
     * to plus the widest width (largest category) of the type used in
     * that register.
     *
     * @return {@code >= 0;} the required registers size
     */
    public int getRegistersSize() {
        int sz = size();
        int result = 0;

        for (int i = 0; i < sz; i++) {
            RegisterSpec spec = (RegisterSpec) get0(i);
            if (spec != null) {
                int min = spec.getNextReg();
                if (min > result) {
                    result = min;
                }
            }
        }

        return result;
    }

    /**
     * Returns a new instance, which is the same as this instance,
     * except that it has an additional element prepended to the original.
     * Mutability of the result is inherited from the original.
     *
     * @param spec {@code non-null;} the new first spec (to prepend)
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public RegisterSpecList withFirst(RegisterSpec spec) {
        int sz = size();
        RegisterSpecList result = new RegisterSpecList(sz + 1);

        for (int i = 0; i < sz; i++) {
            result.set0(i + 1, get0(i));
        }

        result.set0(0, spec);
        if (isImmutable()) {
            result.setImmutable();
        }

        return result;
    }

    /**
     * Returns a new instance, which is the same as this instance,
     * except that its first element is removed. Mutability of the
     * result is inherited from the original.
     *
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public RegisterSpecList withoutFirst() {
        int newSize = size() - 1;

        if (newSize == 0) {
            return EMPTY;
        }

        RegisterSpecList result = new RegisterSpecList(newSize);

        for (int i = 0; i < newSize; i++) {
            result.set0(i, get0(i + 1));
        }

        if (isImmutable()) {
            result.setImmutable();
        }

        return result;
    }

    /**
     * Returns a new instance, which is the same as this instance,
     * except that its last element is removed. Mutability of the
     * result is inherited from the original.
     *
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public RegisterSpecList withoutLast() {
        int newSize = size() - 1;

        if (newSize == 0) {
            return EMPTY;
        }

        RegisterSpecList result = new RegisterSpecList(newSize);

        for (int i = 0; i < newSize; i++) {
            result.set0(i, get0(i));
        }

        if (isImmutable()) {
            result.setImmutable();
        }

        return result;
    }

    /**
     * Returns an instance that is identical to this one, except that
     * all register numbers are offset by the given amount. Mutability
     * of the result is inherited from the original.
     *
     * @param delta the amount to offset the register numbers by
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public RegisterSpecList withOffset(int delta) {
        int sz = size();

        if (sz == 0) {
            // Don't bother making a new zero-element instance.
            return this;
        }

        RegisterSpecList result = new RegisterSpecList(sz);

        for (int i = 0; i < sz; i++) {
            RegisterSpec one = (RegisterSpec) get0(i);
            if (one != null) {
                result.set0(i, one.withOffset(delta));
            }
        }

        if (isImmutable()) {
            result.setImmutable();
        }

        return result;
    }

    /**
     * Returns an instance that is identical to this one, except that
     * all register numbers are renumbered sequentially from the given
     * base, with the first number duplicated if indicated.
     *
     * @param base the base register number
     * @param duplicateFirst whether to duplicate the first number
     * @return {@code non-null;} an appropriately-constructed instance
     */
    public RegisterSpecList withSequentialRegisters(int base,
                                                    boolean duplicateFirst) {
        int sz = size();

        if (sz == 0) {
            // Don't bother making a new zero-element instance.
            return this;
        }

        RegisterSpecList result = new RegisterSpecList(sz);

        for (int i = 0; i < sz; i++) {
            RegisterSpec one = (RegisterSpec) get0(i);
            result.set0(i, one.withReg(base));
            if (duplicateFirst) {
                duplicateFirst = false;
            } else {
                base += one.getCategory();
            }
        }

        if (isImmutable()) {
            result.setImmutable();
        }

        return result;
    }

}
