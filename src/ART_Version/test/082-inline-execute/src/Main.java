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

import junit.framework.Assert;
import java.util.Arrays;
import java.lang.reflect.Method;

public class Main {
  public static void main(String args[]) throws Exception {
    test_Double_doubleToRawLongBits();
    test_Double_longBitsToDouble();
    test_Float_floatToRawIntBits();
    test_Float_intBitsToFloat();
    test_Math_abs_I();
    test_Math_abs_J();
    test_Math_min_I();
    test_Math_max_I();
    test_Math_min_J();
    test_Math_max_J();
    test_Math_min_F();
    test_Math_max_F();
    test_Math_min_D();
    test_Math_max_D();
    test_Math_ceil();
    test_Math_floor();
    test_Math_rint();
    test_Math_round_D();
    test_Math_round_F();
    test_Short_reverseBytes();
    test_Integer_reverseBytes();
    test_Long_reverseBytes();
    test_Integer_reverse();
    test_Long_reverse();
    test_StrictMath_abs_I();
    test_StrictMath_abs_J();
    test_StrictMath_min_I();
    test_StrictMath_max_I();
    test_StrictMath_min_J();
    test_StrictMath_max_J();
    test_StrictMath_min_F();
    test_StrictMath_max_F();
    test_StrictMath_min_D();
    test_StrictMath_max_D();
    test_StrictMath_ceil();
    test_StrictMath_floor();
    test_StrictMath_rint();
    test_StrictMath_round_D();
    test_StrictMath_round_F();
    test_String_charAt();
    test_String_compareTo();
    test_String_indexOf();
    test_String_isEmpty();
    test_String_length();
    test_Thread_currentThread();
    initSupportMethodsForPeekPoke();
    test_Memory_peekByte();
    test_Memory_peekShort();
    test_Memory_peekInt();
    test_Memory_peekLong();
    test_Memory_pokeByte();
    test_Memory_pokeShort();
    test_Memory_pokeInt();
    test_Memory_pokeLong();
  }

  /**
   * Will test inlining Thread.currentThread().
   */
  public static void test_Thread_currentThread() {
    // 1. Do not use result.
    Thread.currentThread();

    // 2. Result should not be null.
    Assert.assertNotNull(Thread.currentThread());
  }

  public static void test_String_length() {
    String str0 = "";
    String str1 = "x";
    String str80 = "01234567890123456789012345678901234567890123456789012345678901234567890123456789";

    Assert.assertEquals(str0.length(), 0);
    Assert.assertEquals(str1.length(), 1);
    Assert.assertEquals(str80.length(), 80);

    String strNull = null;
    try {
      strNull.length();
      Assert.fail();
    } catch (NullPointerException expected) {
    }
  }

  public static void test_String_isEmpty() {
    String str0 = "";
    String str1 = "x";

    Assert.assertTrue(str0.isEmpty());
    Assert.assertFalse(str1.isEmpty());

    String strNull = null;
    try {
      strNull.isEmpty();
      Assert.fail();
    } catch (NullPointerException expected) {
    }
  }

  public static void test_String_charAt() {
    String testStr = "Now is the time";

    Assert.assertEquals('N', testStr.charAt(0));
    Assert.assertEquals('o', testStr.charAt(1));
    Assert.assertEquals(' ', testStr.charAt(10));
    Assert.assertEquals('e', testStr.charAt(testStr.length()-1));

    try {
      testStr.charAt(-1);
      Assert.fail();
    } catch (StringIndexOutOfBoundsException expected) {
    }
    try {
      testStr.charAt(80);
      Assert.fail();
    } catch (StringIndexOutOfBoundsException expected) {
    }

    String strNull = null;
    try {
      strNull.charAt(0);
      Assert.fail();
    } catch (NullPointerException expected) {
    }
  }

  static int start;
  private static int[] negIndex = { -100000 };
  public static void test_String_indexOf() {
    String str0 = "";
    String str1 = "/";
    String str3 = "abc";
    String str10 = "abcdefghij";
    String str40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc";

    int supplementaryChar = 0x20b9f;
    String surrogatePair = "\ud842\udf9f";
    String stringWithSurrogates = "hello " + surrogatePair + " world";

    Assert.assertEquals(stringWithSurrogates.indexOf(supplementaryChar), "hello ".length());
    Assert.assertEquals(stringWithSurrogates.indexOf(supplementaryChar, 2), "hello ".length());
    Assert.assertEquals(stringWithSurrogates.indexOf(supplementaryChar, 6), 6);
    Assert.assertEquals(stringWithSurrogates.indexOf(supplementaryChar, 7), -1);

    Assert.assertEquals(str0.indexOf('a'), -1);
    Assert.assertEquals(str3.indexOf('a'), 0);
    Assert.assertEquals(str3.indexOf('b'), 1);
    Assert.assertEquals(str3.indexOf('c'), 2);
    Assert.assertEquals(str10.indexOf('j'), 9);
    Assert.assertEquals(str40.indexOf('a'), 0);
    Assert.assertEquals(str40.indexOf('b'), 38);
    Assert.assertEquals(str40.indexOf('c'), 39);
    Assert.assertEquals(str0.indexOf('a',20), -1);
    Assert.assertEquals(str0.indexOf('a',0), -1);
    Assert.assertEquals(str0.indexOf('a',-1), -1);
    Assert.assertEquals(str1.indexOf('/',++start), -1);
    Assert.assertEquals(str1.indexOf('a',negIndex[0]), -1);
    Assert.assertEquals(str3.indexOf('a',0), 0);
    Assert.assertEquals(str3.indexOf('a',1), -1);
    Assert.assertEquals(str3.indexOf('a',1234), -1);
    Assert.assertEquals(str3.indexOf('b',0), 1);
    Assert.assertEquals(str3.indexOf('b',1), 1);
    Assert.assertEquals(str3.indexOf('c',2), 2);
    Assert.assertEquals(str10.indexOf('j',5), 9);
    Assert.assertEquals(str10.indexOf('j',9), 9);
    Assert.assertEquals(str40.indexOf('a',10), 10);
    Assert.assertEquals(str40.indexOf('b',40), -1);

    String strNull = null;
    try {
      strNull.indexOf('a');
      Assert.fail();
    } catch (NullPointerException expected) {
    }
    try {
      strNull.indexOf('a', 0);
      Assert.fail();
    } catch (NullPointerException expected) {
    }
    try {
      strNull.indexOf('a', -1);
      Assert.fail();
    } catch (NullPointerException expected) {
    }
  }

  public static void test_String_compareTo() {
    String test = "0123456789";
    String test1 = new String("0123456789");    // different object
    String test2 = new String("0123456780");    // different value
    String offset = new String("xxx0123456789yyy");
    String sub = offset.substring(3, 13);
    String str32 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    String str33 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy";
    String lc = "abcdefg";
    String uc = "ABCDEFG";
    Object blah = new Object();

    Assert.assertTrue(lc.toUpperCase().equals(uc));

    Assert.assertEquals(str32.compareTo(str33), -1);
    Assert.assertEquals(str33.compareTo(str32), 1);

    Assert.assertTrue(test.equals(test));
    Assert.assertTrue(test.equals(test1));
    Assert.assertFalse(test.equals(test2));

    Assert.assertEquals(test.compareTo(test1), 0);
    Assert.assertTrue(test1.compareTo(test2) > 0);
    Assert.assertTrue(test2.compareTo(test1) < 0);

    // Compare string with a nonzero offset, in left/right side.
    Assert.assertEquals(test.compareTo(sub), 0);
    Assert.assertEquals(sub.compareTo(test), 0);
    Assert.assertTrue(test.equals(sub));
    Assert.assertTrue(sub.equals(test));
    // Same base, one is a substring.
    Assert.assertFalse(offset.equals(sub));
    Assert.assertFalse(sub.equals(offset));
    // Wrong class.
    Assert.assertFalse(test.equals(blah));

    // Null lhs - throw.
    try {
      test.compareTo(null);
      Assert.fail("didn't get expected npe");
    } catch (NullPointerException npe) {
    }
    // Null rhs - okay.
    Assert.assertFalse(test.equals(null));

    test = test.substring(1);
    Assert.assertTrue(test.equals("123456789"));
    Assert.assertFalse(test.equals(test1));

    test = test.substring(1);
    Assert.assertTrue(test.equals("23456789"));

    test = test.substring(1);
    Assert.assertTrue(test.equals("3456789"));

    test = test.substring(1);
    Assert.assertTrue(test.equals("456789"));

    test = test.substring(3,5);
    Assert.assertTrue(test.equals("78"));

    test = "this/is/a/path";
    String[] strings = test.split("/");
    Assert.assertEquals(4, strings.length);

    Assert.assertEquals("this is a path", test.replaceAll("/", " "));
    Assert.assertEquals("this is a path", test.replace("/", " "));
  }

  public static void test_Math_abs_I() {
    Assert.assertEquals(Math.abs(0), 0);
    Assert.assertEquals(Math.abs(123), 123);
    Assert.assertEquals(Math.abs(-123), 123);
    Assert.assertEquals(Math.abs(Integer.MAX_VALUE), Integer.MAX_VALUE);
    Assert.assertEquals(Math.abs(Integer.MIN_VALUE), Integer.MIN_VALUE);
    Assert.assertEquals(Math.abs(Integer.MIN_VALUE - 1), Integer.MAX_VALUE);
    Assert.assertEquals(Math.abs(Integer.MIN_VALUE + 1), Integer.MAX_VALUE);
  }

  public static void test_Math_abs_J() {
    Assert.assertEquals(Math.abs(0L), 0L);
    Assert.assertEquals(Math.abs(123L), 123L);
    Assert.assertEquals(Math.abs(-123L), 123L);
    Assert.assertEquals(Math.abs(Long.MAX_VALUE), Long.MAX_VALUE);
    Assert.assertEquals(Math.abs(Long.MIN_VALUE), Long.MIN_VALUE);
    Assert.assertEquals(Math.abs(Long.MIN_VALUE - 1), Long.MAX_VALUE);
  }

  public static void test_Math_min_I() {
    Assert.assertEquals(Math.min(0, 0), 0);
    Assert.assertEquals(Math.min(1, 0), 0);
    Assert.assertEquals(Math.min(0, 1), 0);
    Assert.assertEquals(Math.min(0, Integer.MAX_VALUE), 0);
    Assert.assertEquals(Math.min(Integer.MIN_VALUE, 0), Integer.MIN_VALUE);
    Assert.assertEquals(Math.min(Integer.MIN_VALUE, Integer.MAX_VALUE), Integer.MIN_VALUE);
  }

  public static void test_Math_max_I() {
    Assert.assertEquals(Math.max(0, 0), 0);
    Assert.assertEquals(Math.max(1, 0), 1);
    Assert.assertEquals(Math.max(0, 1), 1);
    Assert.assertEquals(Math.max(0, Integer.MAX_VALUE), Integer.MAX_VALUE);
    Assert.assertEquals(Math.max(Integer.MIN_VALUE, 0), 0);
    Assert.assertEquals(Math.max(Integer.MIN_VALUE, Integer.MAX_VALUE), Integer.MAX_VALUE);
  }

  public static void test_Math_min_J() {
    Assert.assertEquals(Math.min(0L, 0L), 0L);
    Assert.assertEquals(Math.min(1L, 0L), 0L);
    Assert.assertEquals(Math.min(0L, 1L), 0L);
    Assert.assertEquals(Math.min(0L, Long.MAX_VALUE), 0L);
    Assert.assertEquals(Math.min(Long.MIN_VALUE, 0L), Long.MIN_VALUE);
    Assert.assertEquals(Math.min(Long.MIN_VALUE, Long.MAX_VALUE), Long.MIN_VALUE);
  }

  public static void test_Math_max_J() {
    Assert.assertEquals(Math.max(0L, 0L), 0L);
    Assert.assertEquals(Math.max(1L, 0L), 1L);
    Assert.assertEquals(Math.max(0L, 1L), 1L);
    Assert.assertEquals(Math.max(0L, Long.MAX_VALUE), Long.MAX_VALUE);
    Assert.assertEquals(Math.max(Long.MIN_VALUE, 0L), 0L);
    Assert.assertEquals(Math.max(Long.MIN_VALUE, Long.MAX_VALUE), Long.MAX_VALUE);
  }

  public static void test_Math_min_F() {
    Assert.assertTrue(Float.isNaN(Math.min(1.0f, Float.NaN)));
    Assert.assertTrue(Float.isNaN(Math.min(Float.NaN, 1.0f)));
    Assert.assertEquals(Math.min(-0.0f, 0.0f), -0.0f);
    Assert.assertEquals(Math.min(0.0f, -0.0f), -0.0f);
    Assert.assertEquals(Math.min(-0.0f, -0.0f), -0.0f);
    Assert.assertEquals(Math.min(0.0f, 0.0f), 0.0f);
    Assert.assertEquals(Math.min(1.0f, 0.0f), 0.0f);
    Assert.assertEquals(Math.min(0.0f, 1.0f), 0.0f);
    Assert.assertEquals(Math.min(0.0f, Float.MAX_VALUE), 0.0f);
    Assert.assertEquals(Math.min(Float.MIN_VALUE, 0.0f), 0.0f);
    Assert.assertEquals(Math.min(Float.MIN_VALUE, Float.MAX_VALUE), Float.MIN_VALUE);
  }

  public static void test_Math_max_F() {
    Assert.assertTrue(Float.isNaN(Math.max(1.0f, Float.NaN)));
    Assert.assertTrue(Float.isNaN(Math.max(Float.NaN, 1.0f)));
    Assert.assertEquals(Math.max(-0.0f, 0.0f), 0.0f);
    Assert.assertEquals(Math.max(0.0f, -0.0f), 0.0f);
    Assert.assertEquals(Math.max(-0.0f, -0.0f), -0.0f);
    Assert.assertEquals(Math.max(0.0f, 0.0f), 0.0f);
    Assert.assertEquals(Math.max(1.0f, 0.0f), 1.0f);
    Assert.assertEquals(Math.max(0.0f, 1.0f), 1.0f);
    Assert.assertEquals(Math.max(0.0f, Float.MAX_VALUE), Float.MAX_VALUE);
    Assert.assertEquals(Math.max(Float.MIN_VALUE, 0.0f), Float.MIN_VALUE);
    Assert.assertEquals(Math.max(Float.MIN_VALUE, Float.MAX_VALUE), Float.MAX_VALUE);
  }

  public static void test_Math_min_D() {
    Assert.assertTrue(Double.isNaN(Math.min(1.0d, Double.NaN)));
    Assert.assertTrue(Double.isNaN(Math.min(Double.NaN, 1.0d)));
    Assert.assertEquals(Math.min(-0.0d, 0.0d), -0.0d);
    Assert.assertEquals(Math.min(0.0d, -0.0d), -0.0d);
    Assert.assertEquals(Math.min(-0.0d, -0.0d), -0.0d);
    Assert.assertEquals(Math.min(0.0d, 0.0d), 0.0d);
    Assert.assertEquals(Math.min(1.0d, 0.0d), 0.0d);
    Assert.assertEquals(Math.min(0.0d, 1.0d), 0.0d);
    Assert.assertEquals(Math.min(0.0d, Double.MAX_VALUE), 0.0d);
    Assert.assertEquals(Math.min(Double.MIN_VALUE, 0.0d), 0.0d);
    Assert.assertEquals(Math.min(Double.MIN_VALUE, Double.MAX_VALUE), Double.MIN_VALUE);
  }

  public static void test_Math_max_D() {
    Assert.assertTrue(Double.isNaN(Math.max(1.0d, Double.NaN)));
    Assert.assertTrue(Double.isNaN(Math.max(Double.NaN, 1.0d)));
    Assert.assertEquals(Math.max(-0.0d, 0.0d), 0.0d);
    Assert.assertEquals(Math.max(0.0d, -0.0d), 0.0d);
    Assert.assertEquals(Math.max(-0.0d, -0.0d), -0.0d);
    Assert.assertEquals(Math.max(0.0d, 0.0d), 0.0d);
    Assert.assertEquals(Math.max(1.0d, 0.0d), 1.0d);
    Assert.assertEquals(Math.max(0.0d, 1.0d), 1.0d);
    Assert.assertEquals(Math.max(0.0d, Double.MAX_VALUE), Double.MAX_VALUE);
    Assert.assertEquals(Math.max(Double.MIN_VALUE, 0.0d), Double.MIN_VALUE);
    Assert.assertEquals(Math.max(Double.MIN_VALUE, Double.MAX_VALUE), Double.MAX_VALUE);
  }

  public static void test_Math_ceil() {
    Assert.assertEquals(Math.ceil(+0.0), +0.0d, 0.0);
    Assert.assertEquals(Math.ceil(-0.0), -0.0d, 0.0);
    Assert.assertEquals(Math.ceil(-0.9), -0.0d, 0.0);
    Assert.assertEquals(Math.ceil(-0.5), -0.0d, 0.0);
    Assert.assertEquals(Math.ceil(0.0), -0.0d, 0.0);
    Assert.assertEquals(Math.ceil(+2.0), +2.0d, 0.0);
    Assert.assertEquals(Math.ceil(+2.1), +3.0d, 0.0);
    Assert.assertEquals(Math.ceil(+2.5), +3.0d, 0.0);
    Assert.assertEquals(Math.ceil(+2.9), +3.0d, 0.0);
    Assert.assertEquals(Math.ceil(+3.0), +3.0d, 0.0);
    Assert.assertEquals(Math.ceil(-2.0), -2.0d, 0.0);
    Assert.assertEquals(Math.ceil(-2.1), -2.0d, 0.0);
    Assert.assertEquals(Math.ceil(-2.5), -2.0d, 0.0);
    Assert.assertEquals(Math.ceil(-2.9), -2.0d, 0.0);
    Assert.assertEquals(Math.ceil(-3.0), -3.0d, 0.0);
    Assert.assertEquals(Math.ceil(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(Math.ceil(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(Math.ceil(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_Math_floor() {
    Assert.assertEquals(Math.floor(+0.0), +0.0d, 0.0);
    Assert.assertEquals(Math.floor(-0.0), -0.0d, 0.0);
    Assert.assertEquals(Math.floor(+2.0), +2.0d, 0.0);
    Assert.assertEquals(Math.floor(+2.1), +2.0d, 0.0);
    Assert.assertEquals(Math.floor(+2.5), +2.0d, 0.0);
    Assert.assertEquals(Math.floor(+2.9), +2.0d, 0.0);
    Assert.assertEquals(Math.floor(+3.0), +3.0d, 0.0);
    Assert.assertEquals(Math.floor(-2.0), -2.0d, 0.0);
    Assert.assertEquals(Math.floor(-2.1), -3.0d, 0.0);
    Assert.assertEquals(Math.floor(-2.5), -3.0d, 0.0);
    Assert.assertEquals(Math.floor(-2.9), -3.0d, 0.0);
    Assert.assertEquals(Math.floor(-3.0), -3.0d, 0.0);
    Assert.assertEquals(Math.floor(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(Math.floor(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(Math.floor(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_Math_rint() {
    Assert.assertEquals(Math.rint(+0.0), +0.0d, 0.0);
    Assert.assertEquals(Math.rint(-0.0), -0.0d, 0.0);
    Assert.assertEquals(Math.rint(+2.0), +2.0d, 0.0);
    Assert.assertEquals(Math.rint(+2.1), +2.0d, 0.0);
    Assert.assertEquals(Math.rint(+2.5), +2.0d, 0.0);
    Assert.assertEquals(Math.rint(+2.9), +3.0d, 0.0);
    Assert.assertEquals(Math.rint(+3.0), +3.0d, 0.0);
    Assert.assertEquals(Math.rint(-2.0), -2.0d, 0.0);
    Assert.assertEquals(Math.rint(-2.1), -2.0d, 0.0);
    Assert.assertEquals(Math.rint(-2.5), -2.0d, 0.0);
    Assert.assertEquals(Math.rint(-2.9), -3.0d, 0.0);
    Assert.assertEquals(Math.rint(-3.0), -3.0d, 0.0);
    Assert.assertEquals(Math.rint(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(Math.rint(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(Math.rint(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_Math_round_D() {
    Assert.assertEquals(Math.round(+0.0d), (long)+0.0);
    Assert.assertEquals(Math.round(-0.0d), (long)+0.0);
    Assert.assertEquals(Math.round(2.0d), 2l);
    Assert.assertEquals(Math.round(2.1d), 2l);
    Assert.assertEquals(Math.round(2.5d), 3l);
    Assert.assertEquals(Math.round(2.9d), 3l);
    Assert.assertEquals(Math.round(3.0d), 3l);
    Assert.assertEquals(Math.round(-2.0d), -2l);
    Assert.assertEquals(Math.round(-2.1d), -2l);
    Assert.assertEquals(Math.round(-2.5d), -2l);
    Assert.assertEquals(Math.round(-2.9d), -3l);
    Assert.assertEquals(Math.round(-3.0d), -3l);
    Assert.assertEquals(Math.round(0.49999999999999994d), 1l);
    Assert.assertEquals(Math.round(Double.NaN), (long)+0.0d);
    Assert.assertEquals(Math.round(Long.MAX_VALUE + 1.0d), Long.MAX_VALUE);
    Assert.assertEquals(Math.round(Long.MIN_VALUE - 1.0d), Long.MIN_VALUE);
    Assert.assertEquals(Math.round(Double.POSITIVE_INFINITY), Long.MAX_VALUE);
    Assert.assertEquals(Math.round(Double.NEGATIVE_INFINITY), Long.MIN_VALUE);
  }

  public static void test_Math_round_F() {
    Assert.assertEquals(Math.round(+0.0f), (int)+0.0);
    Assert.assertEquals(Math.round(-0.0f), (int)+0.0);
    Assert.assertEquals(Math.round(2.0f), 2);
    Assert.assertEquals(Math.round(2.1f), 2);
    Assert.assertEquals(Math.round(2.5f), 3);
    Assert.assertEquals(Math.round(2.9f), 3);
    Assert.assertEquals(Math.round(3.0f), 3);
    Assert.assertEquals(Math.round(-2.0f), -2);
    Assert.assertEquals(Math.round(-2.1f), -2);
    Assert.assertEquals(Math.round(-2.5f), -2);
    Assert.assertEquals(Math.round(-2.9f), -3);
    Assert.assertEquals(Math.round(-3.0f), -3);
    Assert.assertEquals(Math.round(Float.NaN), (int)+0.0f);
    Assert.assertEquals(Math.round(Integer.MAX_VALUE + 1.0f), Integer.MAX_VALUE);
    Assert.assertEquals(Math.round(Integer.MIN_VALUE - 1.0f), Integer.MIN_VALUE);
    Assert.assertEquals(Math.round(Float.POSITIVE_INFINITY), Integer.MAX_VALUE);
    Assert.assertEquals(Math.round(Float.NEGATIVE_INFINITY), Integer.MIN_VALUE);
  }

  public static void test_StrictMath_abs_I() {
    Assert.assertEquals(StrictMath.abs(0), 0);
    Assert.assertEquals(StrictMath.abs(123), 123);
    Assert.assertEquals(StrictMath.abs(-123), 123);
    Assert.assertEquals(StrictMath.abs(Integer.MAX_VALUE), Integer.MAX_VALUE);
    Assert.assertEquals(StrictMath.abs(Integer.MIN_VALUE), Integer.MIN_VALUE);
    Assert.assertEquals(StrictMath.abs(Integer.MIN_VALUE - 1), Integer.MAX_VALUE);
    Assert.assertEquals(StrictMath.abs(Integer.MIN_VALUE + 1), Integer.MAX_VALUE);
  }

  public static void test_StrictMath_abs_J() {
    Assert.assertEquals(StrictMath.abs(0L), 0L);
    Assert.assertEquals(StrictMath.abs(123L), 123L);
    Assert.assertEquals(StrictMath.abs(-123L), 123L);
    Assert.assertEquals(StrictMath.abs(Long.MAX_VALUE), Long.MAX_VALUE);
    Assert.assertEquals(StrictMath.abs(Long.MIN_VALUE), Long.MIN_VALUE);
    Assert.assertEquals(StrictMath.abs(Long.MIN_VALUE - 1), Long.MAX_VALUE);
  }

  public static void test_StrictMath_min_I() {
    Assert.assertEquals(StrictMath.min(0, 0), 0);
    Assert.assertEquals(StrictMath.min(1, 0), 0);
    Assert.assertEquals(StrictMath.min(0, 1), 0);
    Assert.assertEquals(StrictMath.min(0, Integer.MAX_VALUE), 0);
    Assert.assertEquals(StrictMath.min(Integer.MIN_VALUE, 0), Integer.MIN_VALUE);
    Assert.assertEquals(StrictMath.min(Integer.MIN_VALUE, Integer.MAX_VALUE), Integer.MIN_VALUE);
  }

  public static void test_StrictMath_max_I() {
    Assert.assertEquals(StrictMath.max(0, 0), 0);
    Assert.assertEquals(StrictMath.max(1, 0), 1);
    Assert.assertEquals(StrictMath.max(0, 1), 1);
    Assert.assertEquals(StrictMath.max(0, Integer.MAX_VALUE), Integer.MAX_VALUE);
    Assert.assertEquals(StrictMath.max(Integer.MIN_VALUE, 0), 0);
    Assert.assertEquals(StrictMath.max(Integer.MIN_VALUE, Integer.MAX_VALUE), Integer.MAX_VALUE);
  }

  public static void test_StrictMath_min_J() {
    Assert.assertEquals(StrictMath.min(0L, 0L), 0L);
    Assert.assertEquals(StrictMath.min(1L, 0L), 0L);
    Assert.assertEquals(StrictMath.min(0L, 1L), 0L);
    Assert.assertEquals(StrictMath.min(0L, Long.MAX_VALUE), 0L);
    Assert.assertEquals(StrictMath.min(Long.MIN_VALUE, 0L), Long.MIN_VALUE);
    Assert.assertEquals(StrictMath.min(Long.MIN_VALUE, Long.MAX_VALUE), Long.MIN_VALUE);
  }

  public static void test_StrictMath_max_J() {
    Assert.assertEquals(StrictMath.max(0L, 0L), 0L);
    Assert.assertEquals(StrictMath.max(1L, 0L), 1L);
    Assert.assertEquals(StrictMath.max(0L, 1L), 1L);
    Assert.assertEquals(StrictMath.max(0L, Long.MAX_VALUE), Long.MAX_VALUE);
    Assert.assertEquals(StrictMath.max(Long.MIN_VALUE, 0L), 0L);
    Assert.assertEquals(StrictMath.max(Long.MIN_VALUE, Long.MAX_VALUE), Long.MAX_VALUE);
  }

  public static void test_StrictMath_min_F() {
    Assert.assertTrue(Float.isNaN(StrictMath.min(1.0f, Float.NaN)));
    Assert.assertTrue(Float.isNaN(StrictMath.min(Float.NaN, 1.0f)));
    Assert.assertEquals(StrictMath.min(-0.0f, 0.0f), -0.0f);
    Assert.assertEquals(StrictMath.min(0.0f, -0.0f), -0.0f);
    Assert.assertEquals(StrictMath.min(-0.0f, -0.0f), -0.0f);
    Assert.assertEquals(StrictMath.min(0.0f, 0.0f), 0.0f);
    Assert.assertEquals(StrictMath.min(1.0f, 0.0f), 0.0f);
    Assert.assertEquals(StrictMath.min(0.0f, 1.0f), 0.0f);
    Assert.assertEquals(StrictMath.min(0.0f, Float.MAX_VALUE), 0.0f);
    Assert.assertEquals(StrictMath.min(Float.MIN_VALUE, 0.0f), 0.0f);
    Assert.assertEquals(StrictMath.min(Float.MIN_VALUE, Float.MAX_VALUE), Float.MIN_VALUE);
  }

  public static void test_StrictMath_max_F() {
    Assert.assertTrue(Float.isNaN(StrictMath.max(1.0f, Float.NaN)));
    Assert.assertTrue(Float.isNaN(StrictMath.max(Float.NaN, 1.0f)));
    Assert.assertEquals(StrictMath.max(-0.0f, 0.0f), 0.0f);
    Assert.assertEquals(StrictMath.max(0.0f, -0.0f), 0.0f);
    Assert.assertEquals(StrictMath.max(-0.0f, -0.0f), -0.0f);
    Assert.assertEquals(StrictMath.max(0.0f, 0.0f), 0.0f);
    Assert.assertEquals(StrictMath.max(1.0f, 0.0f), 1.0f);
    Assert.assertEquals(StrictMath.max(0.0f, 1.0f), 1.0f);
    Assert.assertEquals(StrictMath.max(0.0f, Float.MAX_VALUE), Float.MAX_VALUE);
    Assert.assertEquals(StrictMath.max(Float.MIN_VALUE, 0.0f), Float.MIN_VALUE);
    Assert.assertEquals(StrictMath.max(Float.MIN_VALUE, Float.MAX_VALUE), Float.MAX_VALUE);
  }

  public static void test_StrictMath_min_D() {
    Assert.assertTrue(Double.isNaN(StrictMath.min(1.0d, Double.NaN)));
    Assert.assertTrue(Double.isNaN(StrictMath.min(Double.NaN, 1.0d)));
    Assert.assertEquals(StrictMath.min(-0.0d, 0.0d), -0.0d);
    Assert.assertEquals(StrictMath.min(0.0d, -0.0d), -0.0d);
    Assert.assertEquals(StrictMath.min(-0.0d, -0.0d), -0.0d);
    Assert.assertEquals(StrictMath.min(0.0d, 0.0d), 0.0d);
    Assert.assertEquals(StrictMath.min(1.0d, 0.0d), 0.0d);
    Assert.assertEquals(StrictMath.min(0.0d, 1.0d), 0.0d);
    Assert.assertEquals(StrictMath.min(0.0d, Double.MAX_VALUE), 0.0d);
    Assert.assertEquals(StrictMath.min(Double.MIN_VALUE, 0.0d), 0.0d);
    Assert.assertEquals(StrictMath.min(Double.MIN_VALUE, Double.MAX_VALUE), Double.MIN_VALUE);
  }

  public static void test_StrictMath_max_D() {
    Assert.assertTrue(Double.isNaN(StrictMath.max(1.0d, Double.NaN)));
    Assert.assertTrue(Double.isNaN(StrictMath.max(Double.NaN, 1.0d)));
    Assert.assertEquals(StrictMath.max(-0.0d, 0.0d), 0.0d);
    Assert.assertEquals(StrictMath.max(0.0d, -0.0d), 0.0d);
    Assert.assertEquals(StrictMath.max(-0.0d, -0.0d), -0.0d);
    Assert.assertEquals(StrictMath.max(0.0d, 0.0d), 0.0d);
    Assert.assertEquals(StrictMath.max(1.0d, 0.0d), 1.0d);
    Assert.assertEquals(StrictMath.max(0.0d, 1.0d), 1.0d);
    Assert.assertEquals(StrictMath.max(0.0d, Double.MAX_VALUE), Double.MAX_VALUE);
    Assert.assertEquals(StrictMath.max(Double.MIN_VALUE, 0.0d), Double.MIN_VALUE);
    Assert.assertEquals(StrictMath.max(Double.MIN_VALUE, Double.MAX_VALUE), Double.MAX_VALUE);
  }

  public static void test_StrictMath_ceil() {
    Assert.assertEquals(StrictMath.ceil(+0.0), +0.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-0.0), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-0.9), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-0.5), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(0.0), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(+2.0), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(+2.1), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(+2.5), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(+2.9), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(+3.0), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-2.0), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-2.1), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-2.5), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-2.9), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(-3.0), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.ceil(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(StrictMath.ceil(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(StrictMath.ceil(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_StrictMath_floor() {
    Assert.assertEquals(StrictMath.floor(+0.0), +0.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-0.0), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(+2.0), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(+2.1), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(+2.5), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(+2.9), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(+3.0), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-2.0), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-2.1), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-2.5), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-2.9), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(-3.0), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.floor(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(StrictMath.floor(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(StrictMath.floor(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_StrictMath_rint() {
    Assert.assertEquals(StrictMath.rint(+0.0), +0.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-0.0), -0.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(+2.0), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(+2.1), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(+2.5), +2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(+2.9), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(+3.0), +3.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-2.0), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-2.1), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-2.5), -2.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-2.9), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(-3.0), -3.0d, 0.0);
    Assert.assertEquals(StrictMath.rint(Double.NaN), Double.NaN, 0.0);
    Assert.assertEquals(StrictMath.rint(Double.POSITIVE_INFINITY), Double.POSITIVE_INFINITY, 0.0);
    Assert.assertEquals(StrictMath.rint(Double.NEGATIVE_INFINITY), Double.NEGATIVE_INFINITY, 0.0);
  }

  public static void test_StrictMath_round_D() {
    Assert.assertEquals(StrictMath.round(+0.0d), (long)+0.0);
    Assert.assertEquals(StrictMath.round(-0.0d), (long)+0.0);
    Assert.assertEquals(StrictMath.round(2.0d), 2l);
    Assert.assertEquals(StrictMath.round(2.1d), 2l);
    Assert.assertEquals(StrictMath.round(2.5d), 3l);
    Assert.assertEquals(StrictMath.round(2.9d), 3l);
    Assert.assertEquals(StrictMath.round(3.0d), 3l);
    Assert.assertEquals(StrictMath.round(-2.0d), -2l);
    Assert.assertEquals(StrictMath.round(-2.1d), -2l);
    Assert.assertEquals(StrictMath.round(-2.5d), -2l);
    Assert.assertEquals(StrictMath.round(-2.9d), -3l);
    Assert.assertEquals(StrictMath.round(-3.0d), -3l);
    Assert.assertEquals(StrictMath.round(0.49999999999999994d), 1l);
    Assert.assertEquals(StrictMath.round(Double.NaN), (long)+0.0d);
    Assert.assertEquals(StrictMath.round(Long.MAX_VALUE + 1.0d), Long.MAX_VALUE);
    Assert.assertEquals(StrictMath.round(Long.MIN_VALUE - 1.0d), Long.MIN_VALUE);
    Assert.assertEquals(StrictMath.round(Double.POSITIVE_INFINITY), Long.MAX_VALUE);
    Assert.assertEquals(StrictMath.round(Double.NEGATIVE_INFINITY), Long.MIN_VALUE);
  }

  public static void test_StrictMath_round_F() {
    Assert.assertEquals(StrictMath.round(+0.0f), (int)+0.0);
    Assert.assertEquals(StrictMath.round(-0.0f), (int)+0.0);
    Assert.assertEquals(StrictMath.round(2.0f), 2);
    Assert.assertEquals(StrictMath.round(2.1f), 2);
    Assert.assertEquals(StrictMath.round(2.5f), 3);
    Assert.assertEquals(StrictMath.round(2.9f), 3);
    Assert.assertEquals(StrictMath.round(3.0f), 3);
    Assert.assertEquals(StrictMath.round(-2.0f), -2);
    Assert.assertEquals(StrictMath.round(-2.1f), -2);
    Assert.assertEquals(StrictMath.round(-2.5f), -2);
    Assert.assertEquals(StrictMath.round(-2.9f), -3);
    Assert.assertEquals(StrictMath.round(-3.0f), -3);
    Assert.assertEquals(StrictMath.round(Float.NaN), (int)+0.0f);
    Assert.assertEquals(StrictMath.round(Integer.MAX_VALUE + 1.0f), Integer.MAX_VALUE);
    Assert.assertEquals(StrictMath.round(Integer.MIN_VALUE - 1.0f), Integer.MIN_VALUE);
    Assert.assertEquals(StrictMath.round(Float.POSITIVE_INFINITY), Integer.MAX_VALUE);
    Assert.assertEquals(StrictMath.round(Float.NEGATIVE_INFINITY), Integer.MIN_VALUE);
  }

  public static void test_Float_floatToRawIntBits() {
    Assert.assertEquals(Float.floatToRawIntBits(-1.0f), 0xbf800000);
    Assert.assertEquals(Float.floatToRawIntBits(0.0f), 0);
    Assert.assertEquals(Float.floatToRawIntBits(1.0f), 0x3f800000);
    Assert.assertEquals(Float.floatToRawIntBits(Float.NaN), 0x7fc00000);
    Assert.assertEquals(Float.floatToRawIntBits(Float.POSITIVE_INFINITY), 0x7f800000);
    Assert.assertEquals(Float.floatToRawIntBits(Float.NEGATIVE_INFINITY), 0xff800000);
  }

  public static void test_Float_intBitsToFloat() {
    Assert.assertEquals(Float.intBitsToFloat(0xbf800000), -1.0f);
    Assert.assertEquals(Float.intBitsToFloat(0x00000000), 0.0f);
    Assert.assertEquals(Float.intBitsToFloat(0x3f800000), 1.0f);
    Assert.assertEquals(Float.intBitsToFloat(0x7fc00000), Float.NaN);
    Assert.assertEquals(Float.intBitsToFloat(0x7f800000), Float.POSITIVE_INFINITY);
    Assert.assertEquals(Float.intBitsToFloat(0xff800000), Float.NEGATIVE_INFINITY);
  }

  public static void test_Double_doubleToRawLongBits() {
    Assert.assertEquals(Double.doubleToRawLongBits(-1.0), 0xbff0000000000000L);
    Assert.assertEquals(Double.doubleToRawLongBits(0.0), 0x0000000000000000L);
    Assert.assertEquals(Double.doubleToRawLongBits(1.0), 0x3ff0000000000000L);
    Assert.assertEquals(Double.doubleToRawLongBits(Double.NaN), 0x7ff8000000000000L);
    Assert.assertEquals(Double.doubleToRawLongBits(Double.POSITIVE_INFINITY), 0x7ff0000000000000L);
    Assert.assertEquals(Double.doubleToRawLongBits(Double.NEGATIVE_INFINITY), 0xfff0000000000000L);
  }

  public static void test_Double_longBitsToDouble() {
    Assert.assertEquals(Double.longBitsToDouble(0xbff0000000000000L), -1.0);
    Assert.assertEquals(Double.longBitsToDouble(0x0000000000000000L), 0.0);
    Assert.assertEquals(Double.longBitsToDouble(0x3ff0000000000000L), 1.0);
    Assert.assertEquals(Double.longBitsToDouble(0x7ff8000000000000L), Double.NaN);
    Assert.assertEquals(Double.longBitsToDouble(0x7ff0000000000000L), Double.POSITIVE_INFINITY);
    Assert.assertEquals(Double.longBitsToDouble(0xfff0000000000000L), Double.NEGATIVE_INFINITY);
  }

  public static void test_Short_reverseBytes() {
      Assert.assertEquals(Short.reverseBytes((short)0x0000), (short)0x0000);
      Assert.assertEquals(Short.reverseBytes((short)0xffff), (short)0xffff);
      Assert.assertEquals(Short.reverseBytes((short)0x8000), (short)0x0080);
      Assert.assertEquals(Short.reverseBytes((short)0x0080), (short)0x8000);
      Assert.assertEquals(Short.reverseBytes((short)0x0123), (short)0x2301);
      Assert.assertEquals(Short.reverseBytes((short)0x4567), (short)0x6745);
      Assert.assertEquals(Short.reverseBytes((short)0x89ab), (short)0xab89);
      Assert.assertEquals(Short.reverseBytes((short)0xcdef), (short)0xefcd);
  }

  public static void test_Integer_reverseBytes() {
      Assert.assertEquals(Integer.reverseBytes(0x00000000), 0x00000000);
      Assert.assertEquals(Integer.reverseBytes(0xffffffff), 0xffffffff);
      Assert.assertEquals(Integer.reverseBytes(0x80000000), 0x00000080);
      Assert.assertEquals(Integer.reverseBytes(0x00000080), 0x80000000);
      Assert.assertEquals(Integer.reverseBytes(0x01234567), 0x67452301);
      Assert.assertEquals(Integer.reverseBytes(0x89abcdef), 0xefcdab89);
  }

  public static void test_Long_reverseBytes() {
      Assert.assertEquals(Long.reverseBytes(0x0000000000000000L), 0x0000000000000000L);
      Assert.assertEquals(Long.reverseBytes(0xffffffffffffffffL), 0xffffffffffffffffL);
      Assert.assertEquals(Long.reverseBytes(0x8000000000000000L), 0x0000000000000080L);
      Assert.assertEquals(Long.reverseBytes(0x0000000000000080L), 0x8000000000000000L);
      Assert.assertEquals(Long.reverseBytes(0x0123456789abcdefL), 0xefcdab8967452301L);
  }

  public static void test_Integer_reverse() {
    Assert.assertEquals(Integer.reverse(1), 0x80000000);
    Assert.assertEquals(Integer.reverse(-1), 0xffffffff);
    Assert.assertEquals(Integer.reverse(0), 0);
    Assert.assertEquals(Integer.reverse(0x12345678), 0x1e6a2c48);
    Assert.assertEquals(Integer.reverse(0x87654321), 0x84c2a6e1);
    Assert.assertEquals(Integer.reverse(Integer.MAX_VALUE), 0xfffffffe);
    Assert.assertEquals(Integer.reverse(Integer.MIN_VALUE), 1);
  }

  public static void test_Long_reverse() {
    Assert.assertEquals(Long.reverse(1L), 0x8000000000000000L);
    Assert.assertEquals(Long.reverse(-1L), 0xffffffffffffffffL);
    Assert.assertEquals(Long.reverse(0L), 0L);
    Assert.assertEquals(Long.reverse(0x1234567812345678L), 0x1e6a2c481e6a2c48L);
    Assert.assertEquals(Long.reverse(0x8765432187654321L), 0x84c2a6e184c2a6e1L);
    Assert.assertEquals(Long.reverse(Long.MAX_VALUE), 0xfffffffffffffffeL);
    Assert.assertEquals(Long.reverse(Long.MIN_VALUE), 1L);
  }

  static Object runtime;
  static Method address_of;
  static Method new_non_movable_array;
  static Method peek_byte;
  static Method peek_short;
  static Method peek_int;
  static Method peek_long;
  static Method poke_byte;
  static Method poke_short;
  static Method poke_int;
  static Method poke_long;

  public static void initSupportMethodsForPeekPoke() throws Exception {
    Class<?> vm_runtime = Class.forName("dalvik.system.VMRuntime");
    Method get_runtime = vm_runtime.getDeclaredMethod("getRuntime");
    runtime = get_runtime.invoke(null);
    address_of = vm_runtime.getDeclaredMethod("addressOf", Object.class);
    new_non_movable_array = vm_runtime.getDeclaredMethod("newNonMovableArray", Class.class, Integer.TYPE);

    Class<?> io_memory = Class.forName("libcore.io.Memory");
    peek_byte = io_memory.getDeclaredMethod("peekByte", Long.TYPE);
    peek_int = io_memory.getDeclaredMethod("peekInt", Long.TYPE, Boolean.TYPE);
    peek_short = io_memory.getDeclaredMethod("peekShort", Long.TYPE, Boolean.TYPE);
    peek_long = io_memory.getDeclaredMethod("peekLong", Long.TYPE, Boolean.TYPE);
    poke_byte = io_memory.getDeclaredMethod("pokeByte", Long.TYPE, Byte.TYPE);
    poke_short = io_memory.getDeclaredMethod("pokeShort", Long.TYPE, Short.TYPE, Boolean.TYPE);
    poke_int = io_memory.getDeclaredMethod("pokeInt", Long.TYPE, Integer.TYPE, Boolean.TYPE);
    poke_long = io_memory.getDeclaredMethod("pokeLong", Long.TYPE, Long.TYPE, Boolean.TYPE);
  }

  public static void test_Memory_peekByte() throws Exception {
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 2);
    b[0] = 0x12;
    b[1] = 0x11;
    long address = (long)address_of.invoke(runtime, b);
    Assert.assertEquals((byte)peek_byte.invoke(null, address), 0x12);
    Assert.assertEquals((byte)peek_byte.invoke(null, address + 1), 0x11);
  }

  public static void test_Memory_peekShort() throws Exception {
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 3);
    b[0] = 0x13;
    b[1] = 0x12;
    b[2] = 0x11;
    long address = (long)address_of.invoke(runtime, b);
    Assert.assertEquals((short)peek_short.invoke(null, address, false), 0x1213);  // Aligned read
    Assert.assertEquals((short)peek_short.invoke(null, address + 1, false), 0x1112);  // Unaligned read
  }

  public static void test_Memory_peekInt() throws Exception {
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 5);
    b[0] = 0x15;
    b[1] = 0x14;
    b[2] = 0x13;
    b[3] = 0x12;
    b[4] = 0x11;
    long address = (long)address_of.invoke(runtime, b);
    Assert.assertEquals((int)peek_int.invoke(null, address, false), 0x12131415);
    Assert.assertEquals((int)peek_int.invoke(null, address + 1, false), 0x11121314);
  }

  public static void test_Memory_peekLong() throws Exception {
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 9);
    b[0] = 0x19;
    b[1] = 0x18;
    b[2] = 0x17;
    b[3] = 0x16;
    b[4] = 0x15;
    b[5] = 0x14;
    b[6] = 0x13;
    b[7] = 0x12;
    b[8] = 0x11;
    long address = (long)address_of.invoke(runtime, b);
    Assert.assertEquals((long)peek_long.invoke(null, address, false), 0x1213141516171819L);
    Assert.assertEquals((long)peek_long.invoke(null, address + 1, false), 0x1112131415161718L);
  }

  public static void test_Memory_pokeByte() throws Exception {
    byte[] r = {0x11, 0x12};
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 2);
    long address = (long)address_of.invoke(runtime, b);
    poke_byte.invoke(null, address, (byte)0x11);
    poke_byte.invoke(null, address + 1, (byte)0x12);
    Assert.assertTrue(Arrays.equals(r, b));
  }

  public static void test_Memory_pokeShort() throws Exception {
    byte[] ra = {0x12, 0x11, 0x13};
    byte[] ru = {0x12, 0x22, 0x21};
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 3);
    long address = (long)address_of.invoke(runtime, b);

    // Aligned write
    b[2] = 0x13;
    poke_short.invoke(null, address, (short)0x1112, false);
    Assert.assertTrue(Arrays.equals(ra, b));

    // Unaligned write
    poke_short.invoke(null, address + 1, (short)0x2122, false);
    Assert.assertTrue(Arrays.equals(ru, b));
  }

  public static void test_Memory_pokeInt() throws Exception {
    byte[] ra = {0x14, 0x13, 0x12, 0x11, 0x15};
    byte[] ru = {0x14, 0x24, 0x23, 0x22, 0x21};
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 5);
    long address = (long)address_of.invoke(runtime, b);

    b[4] = 0x15;
    poke_int.invoke(null, address, (int)0x11121314, false);
    Assert.assertTrue(Arrays.equals(ra, b));

    poke_int.invoke(null, address + 1, (int)0x21222324, false);
    Assert.assertTrue(Arrays.equals(ru, b));
  }

  public static void test_Memory_pokeLong() throws Exception {
    byte[] ra = {0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x19};
    byte[] ru = {0x18, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21};
    byte[] b = (byte[])new_non_movable_array.invoke(runtime, Byte.TYPE, 9);
    long address = (long)address_of.invoke(runtime, b);

    b[8] = 0x19;
    poke_long.invoke(null, address, (long)0x1112131415161718L, false);
    Assert.assertTrue(Arrays.equals(ra, b));

    poke_long.invoke(null, address + 1, (long)0x2122232425262728L, false);
    Assert.assertTrue(Arrays.equals(ru, b));
  }
}
