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

import java.lang.reflect.Type;

/**
 * Throw a few things at the verifier, all of which are expected to pass.
 */
public class Main {
    static public void main(String[] args) {
        tryBlah(1);

        System.out.println("Zorch.");
        System.out.println("10 == " + instanceOfTest(10));
    }

    /*
     * Make sure the verifier is handling type merge of arrays of
     * references correctly.
     */
    static Object[] arrayCheck1(int wanted) {
        String[] arrayOne;
        Integer[] arrayTwo;

        arrayOne = new String[1];
        arrayTwo = new Integer[1];

        switch (wanted) {
            case 0:     return arrayOne;
            case 1:     return arrayTwo;
            default:    return null;
        }
    }

    static Object arrayCheck1b(int wanted) {
        String[] arrayOne;
        Integer[] arrayTwo;
        int[] arrayThree;

        arrayOne = new String[1];
        arrayTwo = new Integer[1];
        arrayThree = new int[1];

        switch (wanted) {
            case 0:     return arrayOne;
            case 1:     return arrayTwo;
            case 2:     return arrayThree;
            default:    return null;
        }
    }

    static Object[] arrayCheck2(int wanted) {
        String[][] arrayOne;
        String[][] arrayTwo;
        Integer[][] arrayThree;

        arrayOne = new String[1][];
        arrayTwo = new String[1][];
        arrayThree = new Integer[1][];

        switch (wanted) {
            case 0:     return arrayOne;
            case 1:     return arrayTwo;
            case 2:     return arrayThree;
            default:    return null;
        }
    }

    static Object[] arrayCheck3(int wanted) {
        String[][] arrayTwo;
        String[][][][] arrayFour;

        arrayTwo = new String[1][];
        arrayFour = new String[1][][][];

        switch (wanted) {
            case 0:     return arrayTwo;
            case 1:     return arrayFour;
            default:    return null;
        }
    }

    /*
     * Check return type merge.
     */
    private Type[] typeTest() {
        if(this == null) {
            return (Class<?>[])null;
        }
        return (Type[])null;
    }


    /*
     * Exercise the blahs.
     */
    static void tryBlah(int num) {
        BlahFeature feature = null;     // interface ref

        switch (num) {
            case 1:
                feature = new BlahOne();
                break;
            default:
                feature = new BlahTwo();
                break;
        }

        feature.doStuff();
    }

    static int instanceOfTest(Integer x) {
      Object y = x;
      if (y instanceof String) {
        // Bug: 15808277
        // Non-sensical instance-of to check merging after the branch doesn't result in a verifier
        // error.
        ((String)y).charAt(0);
      }
      return x.intValue();
    }
}
