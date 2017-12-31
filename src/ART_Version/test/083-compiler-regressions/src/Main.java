/*
 * Copyright (C) 2009 The Android Open Source Project
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

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Test for Jit regressions.
 */
public class Main {
    public static int const0x1234() {
        return 0x1234;
    }

    public static long const0x123443211234() {
        return 0x123443211234L;
    }

    public static void main(String args[]) throws Exception {
        b17630605();
        b17411468();
        b2296099Test();
        b2302318Test();
        b2487514Test();
        b5884080Test();
        b13679511Test();
        b16177324TestWrapper();
        b16230771TestWrapper();
        largeFrameTest();
        largeFrameTestFloat();
        mulBy1Test();
        constantPropagationTest();
        getterSetterTest();
        identityTest();
        wideGetterSetterTest();
        wideIdentityTest();
        returnConstantTest();
        setterTestWithReturnArgIgnoreReturn();
        setterTestWithReturnArgUseReturn();
        wideSetterTestWithReturnArgIgnoreReturn();
        wideSetterTestWithReturnArgUseReturn();
        LVNTests.testNPE1();
        LVNTests.testNPE2();
        ZeroTests.longDivTest();
        ZeroTests.longModTest();
        MirOpSelectTests.testIfCcz();
        ManyFloatArgs();
        atomicLong();
        LiveFlags.test();
        minDoubleWith3ConstsTest();
    }

    public static void b17630605() {
      // b/17630605 - failure to properly handle min long immediates.
      long a1 = 40455547223404749L;
      long a2 = Long.MIN_VALUE;
      long answer = a1 + a2;
      if (answer == -9182916489631371059L) {
          System.out.println("b17630605 passes");
      } else {
          System.out.println("b17630605 fails: " + answer);
      }
    }

    public static void b17411468() {
      // b/17411468 - inline Math.round failure.
      double d1 = 1.0;
      double d2 = Math.round(d1);
      if (d1 == d2) {
        System.out.println("b17411468 passes");
      } else {
        System.out.println("b17411468 fails: Math.round(" + d1 + ") returned " + d2);
      }
    }

    public static double minDouble(double a, double b, double c) {
        return Math.min(Math.min(a, b), c);
    }

    public static void minDoubleWith3ConstsTest() {
        double result = minDouble(1.2, 2.5, Double.NaN);
        if (Double.isNaN(result)) {
            System.out.println("minDoubleWith3ConstsTest passes");
        } else {
            System.out.println("minDoubleWith3ConstsTest fails: " + result +
                               " (expecting NaN)");
        }
    }

    public static void atomicLong() {
        AtomicLong atomicLong = new AtomicLong();
        atomicLong.addAndGet(3);
        atomicLong.addAndGet(2);
        atomicLong.addAndGet(1);
        long result = atomicLong.get();
        System.out.println(result == 6L ? "atomicLong passes" :
          ("atomicLong failes: returns " + result + ", expected 6")
        );
    }

    public static void returnConstantTest() {
        long res = const0x1234();
        res += const0x123443211234();
        Foo foo = new Foo();
        res += foo.iConst0x1234();
        res += foo.iConst0x123443211234();
        if (res == 40031347689680L) {
            System.out.println("returnConstantTest passes");
        }
        else {
            System.out.println("returnConstantTest fails: " + res +
                               " (expecting 40031347689680)");
        }
    }

    static void wideIdentityTest() {
        Foo foo = new Foo();
        long i = 0x200000001L;
        i += foo.wideIdent0(i);
        i += foo.wideIdent1(0,i);
        i += foo.wideIdent2(0,0,i);
        i += foo.wideIdent3(0,0,0,i);
        i += foo.wideIdent4(0,0,0,0,i);
        i += foo.wideIdent5(0,0,0,0,0,i);
        if (i == 0x8000000040L) {
            System.out.println("wideIdentityTest passes");
        }
        else {
            System.out.println("wideIdentityTest fails: 0x" + Long.toHexString(i) +
                               " (expecting 0x8000000040)");
        }
    }

    static void wideGetterSetterTest() {
        Foo foo = new Foo();
        long sum = foo.wideGetBar0();
        sum += foo.wideGetBar1(1);
        foo.wideSetBar1(sum);
        sum += foo.wideGetBar2(1,2);
        foo.wideSetBar2(0,sum);
        sum += foo.wideGetBar3(1,2,3);
        foo.wideSetBar3(0,0,sum);
        sum += foo.wideGetBar4(1,2,3,4);
        foo.wideSetBar4(0,0,0,sum);
        sum += foo.wideGetBar5(1,2,3,4,5);
        foo.wideSetBar5(0,0,0,0,sum);
        long result1 = foo.wideGetBar0();
        long expected1 = 1234L << 5;
        sum += foo.wideGetBar0();
        foo.wideSetBar2i(0,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3i(0,0,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4i(0,0,0,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5i(0,0,0,0,sum);
        long result2 = foo.wideGetBar0();
        long expected2 = 1234L << 9;
        if (result1 == expected1 && result2 == expected2) {
            System.out.println("wideGetterSetterTest passes");
        }
        else {
            System.out.println("wideGetterSetterTest fails: " +
                                "result1: " + result1 + " (expecting " + expected1 + "), " +
                                "result2: " + result2 + " (expecting " + expected2 + ")");
        }
    }

    static void identityTest() {
        Foo foo = new Foo();
        int i = 1;
        i += foo.ident0(i);
        i += foo.ident1(0,i);
        i += foo.ident2(0,0,i);
        i += foo.ident3(0,0,0,i);
        i += foo.ident4(0,0,0,0,i);
        i += foo.ident5(0,0,0,0,0,i);
        if (i == 64) {
            System.out.println("identityTest passes");
        }
        else {
            System.out.println("identityTest fails: " + i +
                               " (expecting 64)");
        }
    }

    static void getterSetterTest() {
        Foo foo = new Foo();
        int sum = foo.getBar0();
        sum += foo.getBar1(1);
        foo.setBar1(sum);
        sum += foo.getBar2(1,2);
        foo.setBar2(0,sum);
        sum += foo.getBar3(1,2,3);
        foo.setBar3(0,0,sum);
        sum += foo.getBar4(1,2,3,4);
        foo.setBar4(0,0,0,sum);
        sum += foo.getBar5(1,2,3,4,5);
        foo.setBar5(0,0,0,0,sum);
        Foo nullFoo = null;
        try {
            sum += Foo.barBar(nullFoo);
        } catch(NullPointerException npe) {
            sum += 404;
        }
        foo.setBar1(sum);
        if (foo.getBar0() == 39892) {
            System.out.println("getterSetterTest passes");
        }
        else {
            System.out.println("getterSetterTest fails: " + foo.getBar0() +
                               " (expecting 39892)");
        }
    }

    static void setterTestWithReturnArgIgnoreReturn() {
        Foo foo = new Foo();
        int sum = foo.getBar0();
        sum += foo.getBar0();
        foo.setBar1ReturnThis(sum);
        sum += foo.getBar0();
        foo.setBar2ReturnThis(1,sum);
        sum += foo.getBar0();
        foo.setBar3ReturnThis(1,2,sum);
        sum += foo.getBar0();
        foo.setBar4ReturnThis(1,2,3,sum);
        sum += foo.getBar0();
        foo.setBar5ReturnThis(1,2,3,4,sum);
        sum += foo.getBar0();
        foo.setBar1ReturnBarArg(sum);
        sum += foo.getBar0();
        foo.setBar2ReturnBarArg(1,sum);
        sum += foo.getBar0();
        foo.setBar3ReturnBarArg(1,2,sum);
        sum += foo.getBar0();
        foo.setBar4ReturnBarArg(1,2,3,sum);
        sum += foo.getBar0();
        foo.setBar5ReturnBarArg(1,2,3,4,sum);
        sum += foo.getBar0();
        foo.setBar2ReturnDummyArg1(1,sum);
        sum += foo.getBar0();
        foo.setBar3ReturnDummyArg2(1,2,sum);
        sum += foo.getBar0();
        foo.setBar4ReturnDummyArg3(1,2,3,sum);
        sum += foo.getBar0();
        foo.setBar5ReturnDummyArg4(1,2,3,4,sum);
        sum += foo.getBar0();
        Foo nullFoo = Foo.getNullFoo();
        try {
            nullFoo.setBar1ReturnThis(sum);
        } catch(NullPointerException npe) {
            sum += 404;
        }
        try {
            nullFoo.setBar2ReturnThis(1, sum);
        } catch(NullPointerException npe) {
            sum += 2 * 404;
        }
        try {
            nullFoo.setBar3ReturnThis(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 3 * 404;
        }
        try {
            nullFoo.setBar4ReturnThis(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 4 * 404;
        }
        try {
            nullFoo.setBar5ReturnThis(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 5 * 404;
        }
        try {
            nullFoo.setBar1ReturnBarArg(sum);
        } catch(NullPointerException npe) {
            sum += 6 * 404;
        }
        try {
            nullFoo.setBar2ReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 7 * 404;
        }
        try {
            nullFoo.setBar3ReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 8 * 404;
        }
        try {
            nullFoo.setBar4ReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 9 * 404;
        }
        try {
            nullFoo.setBar5ReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 10 * 404;
        }
        try {
            nullFoo.setBar2ReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 11 * 404;
        }
        try {
            nullFoo.setBar3ReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 12 * 404;
        }
        try {
            nullFoo.setBar4ReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 13 * 404;
        }
        try {
            nullFoo.setBar5ReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 14 * 404;
        }
        int expected = (1234 << 15) + 404 * (15 * 14 / 2);
        if (sum == expected) {
            System.out.println("setterTestWithReturnArgIgnoreReturn passes");
        }
        else {
            System.out.println("setterTestWithReturnArgIgnoreReturn fails: " + sum +
                               " (expecting " + expected + ")");
        }
    }

    static void setterTestWithReturnArgUseReturn() {
        Foo foo = new Foo();
        int sum = foo.getBar0();
        int sumDummy = 0;
        sum += foo.getBar0();
        Foo foo2 = foo.setBar1ReturnThis(sum);
        sum += foo2.getBar0();
        foo = foo2.setBar2ReturnThis(1,sum);
        sum += foo.getBar0();
        foo2 = foo.setBar3ReturnThis(1,2,sum);
        sum += foo2.getBar0();
        foo = foo2.setBar4ReturnThis(1,2,3,sum);
        sum += foo.getBar0();
        foo = foo.setBar5ReturnThis(1,2,3,4,sum);
        sum += foo.getBar0();
        sum += foo.setBar1ReturnBarArg(sum);
        sum += foo.getBar0();
        sum += foo.setBar2ReturnBarArg(1,sum);
        sum += foo.getBar0();
        sum += foo.setBar3ReturnBarArg(1,2,sum);
        sum += foo.getBar0();
        sum += foo.setBar4ReturnBarArg(1,2,3,sum);
        sum += foo.getBar0();
        sum += foo.setBar5ReturnBarArg(1,2,3,4,sum);
        sum += foo.getBar0();
        sumDummy += foo.setBar2ReturnDummyArg1(1,sum);
        sum += foo.getBar0();
        sumDummy += foo.setBar3ReturnDummyArg2(1,2,sum);
        sum += foo.getBar0();
        sumDummy += foo.setBar4ReturnDummyArg3(1,2,3,sum);
        sum += foo.getBar0();
        sumDummy += foo.setBar5ReturnDummyArg4(1,2,3,4,sum);
        sum += foo.getBar0();
        Foo nullFoo = Foo.getNullFoo();
        try {
            foo = nullFoo.setBar1ReturnThis(sum);
        } catch(NullPointerException npe) {
            sum += 404;
        }
        try {
            foo = nullFoo.setBar2ReturnThis(1, sum);
        } catch(NullPointerException npe) {
            sum += 2 * 404;
        }
        try {
            foo = nullFoo.setBar3ReturnThis(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 3 * 404;
        }
        try {
            foo = nullFoo.setBar4ReturnThis(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 4 * 404;
        }
        try {
            foo = nullFoo.setBar5ReturnThis(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 5 * 404;
        }
        try {
            sum += nullFoo.setBar1ReturnBarArg(sum);
        } catch(NullPointerException npe) {
            sum += 6 * 404;
        }
        try {
            sum += nullFoo.setBar2ReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 7 * 404;
        }
        try {
            sum += nullFoo.setBar3ReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 8 * 404;
        }
        try {
            sum += nullFoo.setBar4ReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 9 * 404;
        }
        try {
            sum += nullFoo.setBar5ReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 10 * 404;
        }
        try {
            sumDummy += nullFoo.setBar2ReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 11 * 404;
        }
        try {
            sumDummy += nullFoo.setBar3ReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 12 * 404;
        }
        try {
            sumDummy += nullFoo.setBar4ReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 13 * 404;
        }
        try {
            sumDummy += nullFoo.setBar5ReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 14 * 404;
        }
        int expected = (1234 << 10) * 3 * 3 * 3 * 3 * 3 + 404 * (15 * 14 / 2);
        int expectedDummy = 5 * 4 / 2;
        if (sum == expected && sumDummy == expectedDummy) {
            System.out.println("setterTestWithReturnArgUseReturn passes");
        }
        else {
            System.out.println("setterTestWithReturnArgUseReturn fails: " + sum +
                               " (expecting " + expected + "), sumDummy = " + sumDummy +
                               "(expecting " + expectedDummy + ")");
        }
    }

    static void wideSetterTestWithReturnArgIgnoreReturn() {
        Foo foo = new Foo();
        long sum = foo.wideGetBar0();
        sum += foo.wideGetBar0();
        foo.wideSetBar1ReturnThis(sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar2ReturnThis(1,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3ReturnThis(1,2,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4ReturnThis(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5ReturnThis(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar1ReturnBarArg(sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar2ReturnBarArg(1,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3ReturnBarArg(1,2,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4ReturnBarArg(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5ReturnBarArg(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar2iReturnBarArg(1,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3iReturnBarArg(1,2,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4iReturnBarArg(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5iReturnBarArg(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar2ReturnDummyArg1(1,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3ReturnDummyArg2(1,2,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4ReturnDummyArg3(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5ReturnDummyArg4(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar2iReturnDummyArg1(1,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar3iReturnDummyArg2(1,2,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar4iReturnDummyArg3(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo.wideSetBar5iReturnDummyArg4(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        Foo nullFoo = Foo.getNullFoo();
        try {
            nullFoo.wideSetBar1ReturnThis(sum);
        } catch(NullPointerException npe) {
            sum += 404;
        }
        try {
            nullFoo.wideSetBar2ReturnThis(1, sum);
        } catch(NullPointerException npe) {
            sum += 2 * 404;
        }
        try {
            nullFoo.wideSetBar3ReturnThis(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 3 * 404;
        }
        try {
            nullFoo.wideSetBar4ReturnThis(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 4 * 404;
        }
        try {
            nullFoo.wideSetBar5ReturnThis(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 5 * 404;
        }
        try {
            nullFoo.wideSetBar1ReturnBarArg(sum);
        } catch(NullPointerException npe) {
            sum += 6 * 404;
        }
        try {
            nullFoo.wideSetBar2ReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 7 * 404;
        }
        try {
            nullFoo.wideSetBar3ReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 8 * 404;
        }
        try {
            nullFoo.wideSetBar4ReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 9 * 404;
        }
        try {
            nullFoo.wideSetBar5ReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 10 * 404;
        }
        try {
            nullFoo.wideSetBar2iReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 11 * 404;
        }
        try {
            nullFoo.wideSetBar3iReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 12 * 404;
        }
        try {
            nullFoo.wideSetBar4iReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 13 * 404;
        }
        try {
            nullFoo.wideSetBar5iReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 14 * 404;
        }
        try {
            nullFoo.wideSetBar2ReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 15 * 404;
        }
        try {
            nullFoo.wideSetBar3ReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 16 * 404;
        }
        try {
            nullFoo.wideSetBar4ReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 17 * 404;
        }
        try {
            nullFoo.wideSetBar5ReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 18 * 404;
        }
        try {
            nullFoo.wideSetBar2iReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 19 * 404;
        }
        try {
            nullFoo.wideSetBar3iReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 20 * 404;
        }
        try {
            nullFoo.wideSetBar4iReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 21 * 404;
        }
        try {
            nullFoo.wideSetBar5iReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 22 * 404;
        }
        long expected = (1234L << 23) + 404 * (23 * 22 / 2);
        if (sum == expected) {
            System.out.println("wideSetterTestWithReturnArgIgnoreReturn passes");
        }
        else {
            System.out.println("wideSetterTestWithReturnArgIgnoreReturn fails: " + sum +
                               " (expecting " + expected + ")");
        }
    }

    static void wideSetterTestWithReturnArgUseReturn() {
        Foo foo = new Foo();
        long sum = foo.wideGetBar0();
        long sumDummy = 0;
        sum += foo.wideGetBar0();
        Foo foo2 = foo.wideSetBar1ReturnThis(sum);
        sum += foo2.wideGetBar0();
        foo = foo2.wideSetBar2ReturnThis(1,sum);
        sum += foo.wideGetBar0();
        foo2 = foo.wideSetBar3ReturnThis(1,2,sum);
        sum += foo2.wideGetBar0();
        foo = foo2.wideSetBar4ReturnThis(1,2,3,sum);
        sum += foo.wideGetBar0();
        foo = foo.wideSetBar5ReturnThis(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar1ReturnBarArg(sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar2ReturnBarArg(1,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar3ReturnBarArg(1,2,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar4ReturnBarArg(1,2,3,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar5ReturnBarArg(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar2iReturnBarArg(1,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar3iReturnBarArg(1,2,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar4iReturnBarArg(1,2,3,sum);
        sum += foo.wideGetBar0();
        sum += foo.wideSetBar5iReturnBarArg(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar2ReturnDummyArg1(1,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar3ReturnDummyArg2(1,2,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar4ReturnDummyArg3(1,2,3,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar5ReturnDummyArg4(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar2iReturnDummyArg1(1,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar3iReturnDummyArg2(1,2,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar4iReturnDummyArg3(1,2,3,sum);
        sum += foo.wideGetBar0();
        sumDummy += foo.wideSetBar5iReturnDummyArg4(1,2,3,4,sum);
        sum += foo.wideGetBar0();
        Foo nullFoo = Foo.getNullFoo();
        try {
            foo = nullFoo.wideSetBar1ReturnThis(sum);
        } catch(NullPointerException npe) {
            sum += 404;
        }
        try {
            foo = nullFoo.wideSetBar2ReturnThis(1, sum);
        } catch(NullPointerException npe) {
            sum += 2 * 404;
        }
        try {
            foo = nullFoo.wideSetBar3ReturnThis(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 3 * 404;
        }
        try {
            foo = nullFoo.wideSetBar4ReturnThis(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 4 * 404;
        }
        try {
            foo = nullFoo.wideSetBar5ReturnThis(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 5 * 404;
        }
        try {
            sum += nullFoo.wideSetBar1ReturnBarArg(sum);
        } catch(NullPointerException npe) {
            sum += 6 * 404;
        }
        try {
            sum += nullFoo.wideSetBar2ReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 7 * 404;
        }
        try {
            sum += nullFoo.wideSetBar3ReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 8 * 404;
        }
        try {
            sum += nullFoo.wideSetBar4ReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 9 * 404;
        }
        try {
            sum += nullFoo.wideSetBar5ReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 10 * 404;
        }
        try {
            sum += nullFoo.wideSetBar2iReturnBarArg(1, sum);
        } catch(NullPointerException npe) {
            sum += 11 * 404;
        }
        try {
            sum += nullFoo.wideSetBar3iReturnBarArg(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 12 * 404;
        }
        try {
            sum += nullFoo.wideSetBar4iReturnBarArg(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 13 * 404;
        }
        try {
            sum += nullFoo.wideSetBar5iReturnBarArg(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 14 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar2ReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 15 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar3ReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 16 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar4ReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 17 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar5ReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 18 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar2iReturnDummyArg1(1, sum);
        } catch(NullPointerException npe) {
            sum += 19 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar3iReturnDummyArg2(1, 2, sum);
        } catch(NullPointerException npe) {
            sum += 20 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar4iReturnDummyArg3(1, 2, 3, sum);
        } catch(NullPointerException npe) {
            sum += 21 * 404;
        }
        try {
            sumDummy += nullFoo.wideSetBar5iReturnDummyArg4(1, 2, 3, 4, sum);
        } catch(NullPointerException npe) {
            sum += 22 * 404;
        }
        long expected = (1234L << 14) * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3  + 404 * (23 * 22 / 2);
        long expectedDummy = 2 * (5 * 4 / 2);
        if (sum == expected && sumDummy == expectedDummy) {
            System.out.println("wideSetterTestWithReturnArgUseReturn passes");
        }
        else {
            System.out.println("wideSetterTestWithReturnArgUseReturn fails: " + sum +
                               " (expecting " + expected + "), sumDummy = " + sumDummy +
                               "(expecting " + expectedDummy + ")");
        }
    }

    static void mulBy1Test() {
        long res;
        long j = 1;
        res = 1 * j + j;
        if (res == 2L) {
            System.out.println("mulBy1Test passes");
        }
        else {
            System.out.println("mulBy1Test fails: " + res +
                               " (expecting 2)");
        }
    }

    static void constantPropagationTest() {
        int i = 1;
        int t = 1;
        float z = 1F;
        long h = 1L;
        int g[] = new int[1];
        int w = 1;
        long f = 0;

        for (int a = 1; a < 100; a++) {
            try {
                i = (int)(z);
                h >>= (0 % t);
            }
            finally {
                w = (int)(2 * (f * 6));
            }
        }

        if (w == 0 && h == 1 && g[0] == 0) {
            System.out.println("constantPropagationTest passes");
        } else {
            System.out.println("constantPropagationTest fails");
        }
    }

    static void b2296099Test() throws Exception {
       int x = -1190771042;
       int dist = 360530809;
       int xl = -1190771042;
       int distl = 360530809;

       for (int i = 0; i < 100000; i++) {
           int b = rotateLeft(x, dist);
           if (b != 1030884493)
               throw new RuntimeException("Unexpected value: " + b
                       + " after " + i + " iterations");
       }
       for (int i = 0; i < 100000; i++) {
           long bl = rotateLeft(xl, distl);
           if (bl != 1030884493)
               throw new RuntimeException("Unexpected value: " + bl
                       + " after " + i + " iterations");
       }
       System.out.println("b2296099 passes");
   }

    static int rotateLeft(int i, int distance) {
        return ((i << distance) | (i >>> (-distance)));
    }

    static void b2302318Test() {
        Runtime.getRuntime().gc();

        SpinThread slow = new SpinThread(Thread.MIN_PRIORITY);
        SpinThread fast1 = new SpinThread(Thread.NORM_PRIORITY);
        SpinThread fast2 = new SpinThread(Thread.MAX_PRIORITY);

        slow.setDaemon(true);
        fast1.setDaemon(true);
        fast2.setDaemon(true);

        fast2.start();
        slow.start();
        fast1.start();
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ie) {/*ignore */}
        Runtime.getRuntime().gc();

        System.out.println("b2302318 passes");
    }

    static void b2487514Test() {
        PriorityBlockingQueue q = new PriorityBlockingQueue(10);
        int catchCount = 0;

        q.offer(new Integer(0));
        /*
         * Warm up the code cache to have toArray() compiled. The key here is
         * to pass a compatible type so that there are no exceptions when
         * executing the method body (ie the APUT_OBJECT bytecode).
         */
        for (int i = 0; i < 1000; i++) {
            Integer[] ints = (Integer[]) q.toArray(new Integer[5]);
        }

        /* Now pass an incompatible type which is guaranteed to throw */
        for (int i = 0; i < 1000; i++) {
            try {
                Object[] obj = q.toArray(new String[5]);
            }
            catch (ArrayStoreException  success) {
                catchCount++;
            }
        }

        if (catchCount == 1000) {
            System.out.println("b2487514 passes");
        }
        else {
            System.out.println("b2487514 fails: catchCount is " + catchCount +
                               " (expecting 1000)");
        }
    }

    static void b5884080Test() {
        int vA = 1;

        int l = 0;
        do
        {
            int k = 0;
            do
                vA += 1;
            while (++k < 100);
        } while (++l < 1000);
        if (vA == 100001) {
            System.out.println("b5884080 passes");
        }
        else {
            System.out.println("b5884080 fails: vA is " + vA +
                               " (expecting 100001)");
        }
    }

    static void b13679511Test() {
       System.out.println("b13679511Test starting");
       int[] nn = { 1, 2, 3, 4 };
       for (int i : nn) {
           System.out.println(i);
       }
       int len = nn.length;
       System.out.println(nn.length);
       System.out.println(nn.length % 3);
       System.out.println(len % 3);
       System.out.println(4 % 3);
       System.out.println((nn.length % 3) != 1);
       System.out.println("b13679511Test finishing");
    }

    static void b16177324TestWrapper() {
      try {
        b16177324Test();
      } catch (NullPointerException expected) {
        System.out.println("b16177324TestWrapper caught NPE as expected.");
      }
    }

    static void b16177324Test() {
      // We need this to be a single BasicBlock. Putting it into a try block would cause it to
      // be split at each insn that can throw. So we do the try-catch in a wrapper function.
      int v1 = B16177324Values.values[0];        // Null-check on array element access.
      int v2 = B16177324ValuesKiller.values[0];  // clinit<>() sets B16177324Values.values to null.
      int v3 = B16177324Values.values[0];        // Should throw NPE.
      // If the null-check for v3 was eliminated we should fail with SIGSEGV.
      System.out.println("Unexpectedly retrieved all values: " + v1 + ", " + v2 + ", " + v3);
    }

    static void b16230771TestWrapper() {
      try {
        b16230771Test();
      } catch (NullPointerException expected) {
        System.out.println("b16230771TestWrapper caught NPE as expected.");
      }
    }

    static void b16230771Test() {
      Integer[] array = { null };
      for (Integer i : array) {
        try {
          int value = i;  // Null check on unboxing should fail.
          System.out.println("Unexpectedly retrieved value " + value);
        } catch (NullPointerException e) {
          int value = i;  // Null check on unboxing should fail.
          // The bug was a missing null check, so this would actually cause SIGSEGV.
          System.out.println("Unexpectedly retrieved value " + value + " in NPE catch handler");
        }
      }
    }

    static double TooManyArgs(
          long l00,
          long l01,
          long l02,
          long l03,
          long l04,
          long l05,
          long l06,
          long l07,
          long l08,
          long l09,
          long l10,
          long l11,
          long l12,
          long l13,
          long l14,
          long l15,
          long l16,
          long l17,
          long l18,
          long l19,
          long l20,
          long l21,
          long l22,
          long l23,
          long l24,
          long l25,
          long l26,
          long l27,
          long l28,
          long l29,
          long l30,
          long l31,
          long l32,
          long l33,
          long l34,
          long l35,
          long l36,
          long l37,
          long l38,
          long l39,
          long l40,
          long l41,
          long l42,
          long l43,
          long l44,
          long l45,
          long l46,
          long l47,
          long l48,
          long l49,
          long ll00,
          long ll01,
          long ll02,
          long ll03,
          long ll04,
          long ll05,
          long ll06,
          long ll07,
          long ll08,
          long ll09,
          long ll10,
          long ll11,
          long ll12,
          long ll13,
          long ll14,
          long ll15,
          long ll16,
          long ll17,
          long ll18,
          long ll19,
          double d01,
          double d02,
          double d03,
          double d04,
          double d05,
          double d06,
          double d07,
          double d08,
          double d09,
          double d10,
          double d11,
          double d12,
          double d13,
          double d14,
          double d15,
          double d16,
          double d17,
          double d18,
          double d19,
          double d20,
          double d21,
          double d22,
          double d23,
          double d24,
          double d25,
          double d26,
          double d27,
          double d28,
          double d29,
          double d30,
          double d31,
          double d32,
          double d33,
          double d34,
          double d35,
          double d36,
          double d37,
          double d38,
          double d39,
          double d40,
          double d41,
          double d42,
          double d43,
          double d44,
          double d45,
          double d46,
          double d47,
          double d48,
          double d49) {
        double res = 0.0;
        double t01 = d49;
        double t02 = 02.0 + t01;
        double t03 = 03.0 + t02;
        double t04 = 04.0 + t03;
        double t05 = 05.0 + t04;
        double t06 = 06.0 + t05;
        double t07 = 07.0 + t06;
        double t08 = 08.0 + t07;
        double t09 = 09.0 + t08;
        double t10 = 10.0 + t09;
        double t11 = 11.0 + t10;
        double t12 = 12.0 + t11;
        double t13 = 13.0 + t12;
        double t14 = 14.0 + t13;
        double t15 = 15.0 + t14;
        double t16 = 16.0 + t15;
        double t17 = 17.0 + t16;
        double t18 = 18.0 + t17;
        double t19 = 19.0 + t18;
        double t20 = 20.0 + t19;
        double t21 = 21.0 + t20;
        double t22 = 22.0 + t21;
        double t23 = 23.0 + t22;
        double t24 = 24.0 + t23;
        double t25 = 25.0 + t24;
        double t26 = 26.0 + t25;
        double t27 = 27.0 + t26;
        double t28 = 28.0 + t27;
        double t29 = 29.0 + t28;
        double t30 = 30.0 + t29;
        double t31 = 31.0 + t30;
        double t32 = 32.0 + t31;
        double t33 = 33.0 + t32;
        double t34 = 34.0 + t33;
        double t35 = 35.0 + t34;
        double t36 = 36.0 + t35;
        double t37 = 37.0 + t36;
        double t38 = 38.0 + t37;
        double t39 = 39.0 + t38;
        double t40 = 40.0 + t39;
        double tt02 = 02.0 + t40;
        double tt03 = 03.0 + tt02;
        double tt04 = 04.0 + tt03;
        double tt05 = 05.0 + tt04;
        double tt06 = 06.0 + tt05;
        double tt07 = 07.0 + tt06;
        double tt08 = 08.0 + tt07;
        double tt09 = 09.0 + tt08;
        double tt10 = 10.0 + tt09;
        double tt11 = 11.0 + tt10;
        double tt12 = 12.0 + tt11;
        double tt13 = 13.0 + tt12;
        double tt14 = 14.0 + tt13;
        double tt15 = 15.0 + tt14;
        double tt16 = 16.0 + tt15;
        double tt17 = 17.0 + tt16;
        double tt18 = 18.0 + tt17;
        double tt19 = 19.0 + tt18;
        double tt20 = 20.0 + tt19;
        double tt21 = 21.0 + tt20;
        double tt22 = 22.0 + tt21;
        double tt23 = 23.0 + tt22;
        double tt24 = 24.0 + tt23;
        double tt25 = 25.0 + tt24;
        double tt26 = 26.0 + tt25;
        double tt27 = 27.0 + tt26;
        double tt28 = 28.0 + tt27;
        double tt29 = 29.0 + tt28;
        double tt30 = 30.0 + tt29;
        double tt31 = 31.0 + tt30;
        double tt32 = 32.0 + tt31;
        double tt33 = 33.0 + tt32;
        double tt34 = 34.0 + tt33;
        double tt35 = 35.0 + tt34;
        double tt36 = 36.0 + tt35;
        double tt37 = 37.0 + tt36;
        double tt38 = 38.0 + tt37;
        double tt39 = 39.0 + tt38;
        double tt40 = 40.0 + tt39;
        double ttt02 = 02.0 + tt40;
        double ttt03 = 03.0 + ttt02;
        double ttt04 = 04.0 + ttt03;
        double ttt05 = 05.0 + ttt04;
        double ttt06 = 06.0 + ttt05;
        double ttt07 = 07.0 + ttt06;
        double ttt08 = 08.0 + ttt07;
        double ttt09 = 09.0 + ttt08;
        double ttt10 = 10.0 + ttt09;
        double ttt11 = 11.0 + ttt10;
        double ttt12 = 12.0 + ttt11;
        double ttt13 = 13.0 + ttt12;
        double ttt14 = 14.0 + ttt13;
        double ttt15 = 15.0 + ttt14;
        double ttt16 = 16.0 + ttt15;
        double ttt17 = 17.0 + ttt16;
        double ttt18 = 18.0 + ttt17;
        double ttt19 = 19.0 + ttt18;
        double ttt20 = 20.0 + ttt19;
        double ttt21 = 21.0 + ttt20;
        double ttt22 = 22.0 + ttt21;
        double ttt23 = 23.0 + ttt22;
        double ttt24 = 24.0 + ttt23;
        double ttt25 = 25.0 + ttt24;
        double ttt26 = 26.0 + ttt25;
        double ttt27 = 27.0 + ttt26;
        double ttt28 = 28.0 + ttt27;
        double ttt29 = 29.0 + ttt28;
        double ttt30 = 30.0 + ttt29;
        double ttt31 = 31.0 + ttt30;
      // Repeatedly use some doubles from the middle of the pack to trigger promotion from frame-passed args.
      for (int i = 0; i < 100; i++) {
         res += d40;
         res += d41;
         res += d42;
         res += d43;
         res += d44;
         res += d45;
         res += d46;
         res += d47;
         res += d48;
      }
      for (int i = 0; i < 100; i++) {
         res += d40;
         res += d41;
         res += d42;
         res += d43;
         res += d44;
         res += d45;
         res += d46;
         res += d47;
         res += d48;
      }
      for (int i = 0; i < 100; i++) {
         res += d40;
         res += d41;
         res += d42;
         res += d43;
         res += d44;
         res += d45;
         res += d46;
         res += d47;
         res += d48;
      }
      for (int i = 0; i < 100; i++) {
         res += d40;
         res += d41;
         res += d42;
         res += d43;
         res += d44;
         res += d45;
         res += d46;
         res += d47;
         res += d48;
      }
      return res + tt40;
   }

    public static void ManyFloatArgs() {
        double res = TooManyArgs(
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0,
                                 13.0, 14.0, 15.0, 16.0, 17.0, 18.0, 19.0, 20.0, 21.0, 22.0, 23.0,
                                 24.0, 25.0, 26.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0, 34.0,
                                 35.0, 36.0, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49);
       if ((long)res == 160087) {
           System.out.println("ManyFloatArgs passes");
       } else {
           System.out.println("ManyFloatArgs fails, expected 160087, got: " + res);
       }
    }
    static long largeFrame() {
        int i0 = 0;
        long l0 = 0;
        int i1 = 1;
        long l1 = 1;
        int i2 = 2;
        long l2 = 2;
        int i3 = 3;
        long l3 = 3;
        int i4 = 4;
        long l4 = 4;
        int i5 = 5;
        long l5 = 5;
        int i6 = 6;
        long l6 = 6;
        int i7 = 7;
        long l7 = 7;
        int i8 = 8;
        long l8 = 8;
        int i9 = 9;
        long l9 = 9;
        int i10 = 10;
        long l10 = 10;
        int i11 = 11;
        long l11 = 11;
        int i12 = 12;
        long l12 = 12;
        int i13 = 13;
        long l13 = 13;
        int i14 = 14;
        long l14 = 14;
        int i15 = 15;
        long l15 = 15;
        int i16 = 16;
        long l16 = 16;
        int i17 = 17;
        long l17 = 17;
        int i18 = 18;
        long l18 = 18;
        int i19 = 19;
        long l19 = 19;
        int i20 = 20;
        long l20 = 20;
        int i21 = 21;
        long l21 = 21;
        int i22 = 22;
        long l22 = 22;
        int i23 = 23;
        long l23 = 23;
        int i24 = 24;
        long l24 = 24;
        int i25 = 25;
        long l25 = 25;
        int i26 = 26;
        long l26 = 26;
        int i27 = 27;
        long l27 = 27;
        int i28 = 28;
        long l28 = 28;
        int i29 = 29;
        long l29 = 29;
        int i30 = 30;
        long l30 = 30;
        int i31 = 31;
        long l31 = 31;
        int i32 = 32;
        long l32 = 32;
        int i33 = 33;
        long l33 = 33;
        int i34 = 34;
        long l34 = 34;
        int i35 = 35;
        long l35 = 35;
        int i36 = 36;
        long l36 = 36;
        int i37 = 37;
        long l37 = 37;
        int i38 = 38;
        long l38 = 38;
        int i39 = 39;
        long l39 = 39;
        int i40 = 40;
        long l40 = 40;
        int i41 = 41;
        long l41 = 41;
        int i42 = 42;
        long l42 = 42;
        int i43 = 43;
        long l43 = 43;
        int i44 = 44;
        long l44 = 44;
        int i45 = 45;
        long l45 = 45;
        int i46 = 46;
        long l46 = 46;
        int i47 = 47;
        long l47 = 47;
        int i48 = 48;
        long l48 = 48;
        int i49 = 49;
        long l49 = 49;
        int i50 = 50;
        long l50 = 50;
        int i51 = 51;
        long l51 = 51;
        int i52 = 52;
        long l52 = 52;
        int i53 = 53;
        long l53 = 53;
        int i54 = 54;
        long l54 = 54;
        int i55 = 55;
        long l55 = 55;
        int i56 = 56;
        long l56 = 56;
        int i57 = 57;
        long l57 = 57;
        int i58 = 58;
        long l58 = 58;
        int i59 = 59;
        long l59 = 59;
        int i60 = 60;
        long l60 = 60;
        int i61 = 61;
        long l61 = 61;
        int i62 = 62;
        long l62 = 62;
        int i63 = 63;
        long l63 = 63;
        int i64 = 64;
        long l64 = 64;
        int i65 = 65;
        long l65 = 65;
        int i66 = 66;
        long l66 = 66;
        int i67 = 67;
        long l67 = 67;
        int i68 = 68;
        long l68 = 68;
        int i69 = 69;
        long l69 = 69;
        int i70 = 70;
        long l70 = 70;
        int i71 = 71;
        long l71 = 71;
        int i72 = 72;
        long l72 = 72;
        int i73 = 73;
        long l73 = 73;
        int i74 = 74;
        long l74 = 74;
        int i75 = 75;
        long l75 = 75;
        int i76 = 76;
        long l76 = 76;
        int i77 = 77;
        long l77 = 77;
        int i78 = 78;
        long l78 = 78;
        int i79 = 79;
        long l79 = 79;
        int i80 = 80;
        long l80 = 80;
        int i81 = 81;
        long l81 = 81;
        int i82 = 82;
        long l82 = 82;
        int i83 = 83;
        long l83 = 83;
        int i84 = 84;
        long l84 = 84;
        int i85 = 85;
        long l85 = 85;
        int i86 = 86;
        long l86 = 86;
        int i87 = 87;
        long l87 = 87;
        int i88 = 88;
        long l88 = 88;
        int i89 = 89;
        long l89 = 89;
        int i90 = 90;
        long l90 = 90;
        int i91 = 91;
        long l91 = 91;
        int i92 = 92;
        long l92 = 92;
        int i93 = 93;
        long l93 = 93;
        int i94 = 94;
        long l94 = 94;
        int i95 = 95;
        long l95 = 95;
        int i96 = 96;
        long l96 = 96;
        int i97 = 97;
        long l97 = 97;
        int i98 = 98;
        long l98 = 98;
        int i99 = 99;
        long l99 = 99;
        int i100 = 100;
        long l100 = 100;
        int i101 = 101;
        long l101 = 101;
        int i102 = 102;
        long l102 = 102;
        int i103 = 103;
        long l103 = 103;
        int i104 = 104;
        long l104 = 104;
        int i105 = 105;
        long l105 = 105;
        int i106 = 106;
        long l106 = 106;
        int i107 = 107;
        long l107 = 107;
        int i108 = 108;
        long l108 = 108;
        int i109 = 109;
        long l109 = 109;
        int i110 = 110;
        long l110 = 110;
        int i111 = 111;
        long l111 = 111;
        int i112 = 112;
        long l112 = 112;
        int i113 = 113;
        long l113 = 113;
        int i114 = 114;
        long l114 = 114;
        int i115 = 115;
        long l115 = 115;
        int i116 = 116;
        long l116 = 116;
        int i117 = 117;
        long l117 = 117;
        int i118 = 118;
        long l118 = 118;
        int i119 = 119;
        long l119 = 119;
        int i120 = 120;
        long l120 = 120;
        int i121 = 121;
        long l121 = 121;
        int i122 = 122;
        long l122 = 122;
        int i123 = 123;
        long l123 = 123;
        int i124 = 124;
        long l124 = 124;
        int i125 = 125;
        long l125 = 125;
        int i126 = 126;
        long l126 = 126;
        int i127 = 127;
        long l127 = 127;
        int i128 = 128;
        long l128 = 128;
        int i129 = 129;
        long l129 = 129;
        int i130 = 130;
        long l130 = 130;
        int i131 = 131;
        long l131 = 131;
        int i132 = 132;
        long l132 = 132;
        int i133 = 133;
        long l133 = 133;
        int i134 = 134;
        long l134 = 134;
        int i135 = 135;
        long l135 = 135;
        int i136 = 136;
        long l136 = 136;
        int i137 = 137;
        long l137 = 137;
        int i138 = 138;
        long l138 = 138;
        int i139 = 139;
        long l139 = 139;
        int i140 = 140;
        long l140 = 140;
        int i141 = 141;
        long l141 = 141;
        int i142 = 142;
        long l142 = 142;
        int i143 = 143;
        long l143 = 143;
        int i144 = 144;
        long l144 = 144;
        int i145 = 145;
        long l145 = 145;
        int i146 = 146;
        long l146 = 146;
        int i147 = 147;
        long l147 = 147;
        int i148 = 148;
        long l148 = 148;
        int i149 = 149;
        long l149 = 149;
        int i150 = 150;
        long l150 = 150;
        int i151 = 151;
        long l151 = 151;
        int i152 = 152;
        long l152 = 152;
        int i153 = 153;
        long l153 = 153;
        int i154 = 154;
        long l154 = 154;
        int i155 = 155;
        long l155 = 155;
        int i156 = 156;
        long l156 = 156;
        int i157 = 157;
        long l157 = 157;
        int i158 = 158;
        long l158 = 158;
        int i159 = 159;
        long l159 = 159;
        int i160 = 160;
        long l160 = 160;
        int i161 = 161;
        long l161 = 161;
        int i162 = 162;
        long l162 = 162;
        int i163 = 163;
        long l163 = 163;
        int i164 = 164;
        long l164 = 164;
        int i165 = 165;
        long l165 = 165;
        int i166 = 166;
        long l166 = 166;
        int i167 = 167;
        long l167 = 167;
        int i168 = 168;
        long l168 = 168;
        int i169 = 169;
        long l169 = 169;
        int i170 = 170;
        long l170 = 170;
        int i171 = 171;
        long l171 = 171;
        int i172 = 172;
        long l172 = 172;
        int i173 = 173;
        long l173 = 173;
        int i174 = 174;
        long l174 = 174;
        int i175 = 175;
        long l175 = 175;
        int i176 = 176;
        long l176 = 176;
        int i177 = 177;
        long l177 = 177;
        int i178 = 178;
        long l178 = 178;
        int i179 = 179;
        long l179 = 179;
        int i180 = 180;
        long l180 = 180;
        int i181 = 181;
        long l181 = 181;
        int i182 = 182;
        long l182 = 182;
        int i183 = 183;
        long l183 = 183;
        int i184 = 184;
        long l184 = 184;
        int i185 = 185;
        long l185 = 185;
        int i186 = 186;
        long l186 = 186;
        int i187 = 187;
        long l187 = 187;
        int i188 = 188;
        long l188 = 188;
        int i189 = 189;
        long l189 = 189;
        int i190 = 190;
        long l190 = 190;
        int i191 = 191;
        long l191 = 191;
        int i192 = 192;
        long l192 = 192;
        int i193 = 193;
        long l193 = 193;
        int i194 = 194;
        long l194 = 194;
        int i195 = 195;
        long l195 = 195;
        int i196 = 196;
        long l196 = 196;
        int i197 = 197;
        long l197 = 197;
        int i198 = 198;
        long l198 = 198;
        int i199 = 199;
        long l199 = 199;
        int i200 = 200;
        long l200 = 200;
        int i201 = 201;
        long l201 = 201;
        int i202 = 202;
        long l202 = 202;
        int i203 = 203;
        long l203 = 203;
        int i204 = 204;
        long l204 = 204;
        int i205 = 205;
        long l205 = 205;
        int i206 = 206;
        long l206 = 206;
        int i207 = 207;
        long l207 = 207;
        int i208 = 208;
        long l208 = 208;
        int i209 = 209;
        long l209 = 209;
        int i210 = 210;
        long l210 = 210;
        int i211 = 211;
        long l211 = 211;
        int i212 = 212;
        long l212 = 212;
        int i213 = 213;
        long l213 = 213;
        int i214 = 214;
        long l214 = 214;
        int i215 = 215;
        long l215 = 215;
        int i216 = 216;
        long l216 = 216;
        int i217 = 217;
        long l217 = 217;
        int i218 = 218;
        long l218 = 218;
        int i219 = 219;
        long l219 = 219;
        int i220 = 220;
        long l220 = 220;
        int i221 = 221;
        long l221 = 221;
        int i222 = 222;
        long l222 = 222;
        int i223 = 223;
        long l223 = 223;
        int i224 = 224;
        long l224 = 224;
        int i225 = 225;
        long l225 = 225;
        int i226 = 226;
        long l226 = 226;
        int i227 = 227;
        long l227 = 227;
        int i228 = 228;
        long l228 = 228;
        int i229 = 229;
        long l229 = 229;
        int i230 = 230;
        long l230 = 230;
        int i231 = 231;
        long l231 = 231;
        int i232 = 232;
        long l232 = 232;
        int i233 = 233;
        long l233 = 233;
        int i234 = 234;
        long l234 = 234;
        int i235 = 235;
        long l235 = 235;
        int i236 = 236;
        long l236 = 236;
        int i237 = 237;
        long l237 = 237;
        int i238 = 238;
        long l238 = 238;
        int i239 = 239;
        long l239 = 239;
        int i240 = 240;
        long l240 = 240;
        int i241 = 241;
        long l241 = 241;
        int i242 = 242;
        long l242 = 242;
        int i243 = 243;
        long l243 = 243;
        int i244 = 244;
        long l244 = 244;
        int i245 = 245;
        long l245 = 245;
        int i246 = 246;
        long l246 = 246;
        int i247 = 247;
        long l247 = 247;
        int i248 = 248;
        long l248 = 248;
        int i249 = 249;
        long l249 = 249;
        int i250 = 250;
        long l250 = 250;
        int i251 = 251;
        long l251 = 251;
        int i252 = 252;
        long l252 = 252;
        int i253 = 253;
        long l253 = 253;
        int i254 = 254;
        long l254 = 254;
        int i255 = 255;
        long l255 = 255;
        int i256 = 256;
        long l256 = 256;
        int i257 = 257;
        long l257 = 257;
        int i258 = 258;
        long l258 = 258;
        int i259 = 259;
        long l259 = 259;
        int i260 = 260;
        long l260 = 260;
        int i261 = 261;
        long l261 = 261;
        int i262 = 262;
        long l262 = 262;
        int i263 = 263;
        long l263 = 263;
        int i264 = 264;
        long l264 = 264;
        int i265 = 265;
        long l265 = 265;
        int i266 = 266;
        long l266 = 266;
        int i267 = 267;
        long l267 = 267;
        int i268 = 268;
        long l268 = 268;
        int i269 = 269;
        long l269 = 269;
        int i270 = 270;
        long l270 = 270;
        int i271 = 271;
        long l271 = 271;
        int i272 = 272;
        long l272 = 272;
        int i273 = 273;
        long l273 = 273;
        int i274 = 274;
        long l274 = 274;
        int i275 = 275;
        long l275 = 275;
        int i276 = 276;
        long l276 = 276;
        int i277 = 277;
        long l277 = 277;
        int i278 = 278;
        long l278 = 278;
        int i279 = 279;
        long l279 = 279;
        int i280 = 280;
        long l280 = 280;
        int i281 = 281;
        long l281 = 281;
        int i282 = 282;
        long l282 = 282;
        int i283 = 283;
        long l283 = 283;
        int i284 = 284;
        long l284 = 284;
        int i285 = 285;
        long l285 = 285;
        int i286 = 286;
        long l286 = 286;
        int i287 = 287;
        long l287 = 287;
        int i288 = 288;
        long l288 = 288;
        int i289 = 289;
        long l289 = 289;
        int i290 = 290;
        long l290 = 290;
        int i291 = 291;
        long l291 = 291;
        int i292 = 292;
        long l292 = 292;
        int i293 = 293;
        long l293 = 293;
        int i294 = 294;
        long l294 = 294;
        int i295 = 295;
        long l295 = 295;
        int i296 = 296;
        long l296 = 296;
        int i297 = 297;
        long l297 = 297;
        int i298 = 298;
        long l298 = 298;
        int i299 = 299;
        long l299 = 299;
        int i300 = 300;
        long l300 = 300;
        int i301 = 301;
        long l301 = 301;
        int i302 = 302;
        long l302 = 302;
        int i303 = 303;
        long l303 = 303;
        int i304 = 304;
        long l304 = 304;
        int i305 = 305;
        long l305 = 305;
        int i306 = 306;
        long l306 = 306;
        int i307 = 307;
        long l307 = 307;
        int i308 = 308;
        long l308 = 308;
        int i309 = 309;
        long l309 = 309;
        int i310 = 310;
        long l310 = 310;
        int i311 = 311;
        long l311 = 311;
        int i312 = 312;
        long l312 = 312;
        int i313 = 313;
        long l313 = 313;
        int i314 = 314;
        long l314 = 314;
        int i315 = 315;
        long l315 = 315;
        int i316 = 316;
        long l316 = 316;
        int i317 = 317;
        long l317 = 317;
        int i318 = 318;
        long l318 = 318;
        int i319 = 319;
        long l319 = 319;
        int i320 = 320;
        long l320 = 320;
        int i321 = 321;
        long l321 = 321;
        int i322 = 322;
        long l322 = 322;
        int i323 = 323;
        long l323 = 323;
        int i324 = 324;
        long l324 = 324;
        int i325 = 325;
        long l325 = 325;
        int i326 = 326;
        long l326 = 326;
        int i327 = 327;
        long l327 = 327;
        int i328 = 328;
        long l328 = 328;
        int i329 = 329;
        long l329 = 329;
        int i330 = 330;
        long l330 = 330;
        int i331 = 331;
        long l331 = 331;
        int i332 = 332;
        long l332 = 332;
        int i333 = 333;
        long l333 = 333;
        int i334 = 334;
        long l334 = 334;
        int i335 = 335;
        long l335 = 335;
        int i336 = 336;
        long l336 = 336;
        int i337 = 337;
        long l337 = 337;
        int i338 = 338;
        long l338 = 338;
        int i339 = 339;
        long l339 = 339;
        int i340 = 340;
        long l340 = 340;
        int i341 = 341;
        long l341 = 341;
        int i342 = 342;
        long l342 = 342;
        int i343 = 343;
        long l343 = 343;
        int i344 = 344;
        long l344 = 344;
        int i345 = 345;
        long l345 = 345;
        int i346 = 346;
        long l346 = 346;
        int i347 = 347;
        long l347 = 347;
        int i348 = 348;
        long l348 = 348;
        int i349 = 349;
        long l349 = 349;
        int i350 = 350;
        long l350 = 350;
        int i351 = 351;
        long l351 = 351;
        int i352 = 352;
        long l352 = 352;
        int i353 = 353;
        long l353 = 353;
        int i354 = 354;
        long l354 = 354;
        int i355 = 355;
        long l355 = 355;
        int i356 = 356;
        long l356 = 356;
        int i357 = 357;
        long l357 = 357;
        int i358 = 358;
        long l358 = 358;
        int i359 = 359;
        long l359 = 359;
        int i360 = 360;
        long l360 = 360;
        int i361 = 361;
        long l361 = 361;
        int i362 = 362;
        long l362 = 362;
        int i363 = 363;
        long l363 = 363;
        int i364 = 364;
        long l364 = 364;
        int i365 = 365;
        long l365 = 365;
        int i366 = 366;
        long l366 = 366;
        int i367 = 367;
        long l367 = 367;
        int i368 = 368;
        long l368 = 368;
        int i369 = 369;
        long l369 = 369;
        int i370 = 370;
        long l370 = 370;
        int i371 = 371;
        long l371 = 371;
        int i372 = 372;
        long l372 = 372;
        int i373 = 373;
        long l373 = 373;
        int i374 = 374;
        long l374 = 374;
        int i375 = 375;
        long l375 = 375;
        int i376 = 376;
        long l376 = 376;
        int i377 = 377;
        long l377 = 377;
        int i378 = 378;
        long l378 = 378;
        int i379 = 379;
        long l379 = 379;
        int i380 = 380;
        long l380 = 380;
        int i381 = 381;
        long l381 = 381;
        int i382 = 382;
        long l382 = 382;
        int i383 = 383;
        long l383 = 383;
        int i384 = 384;
        long l384 = 384;
        int i385 = 385;
        long l385 = 385;
        int i386 = 386;
        long l386 = 386;
        int i387 = 387;
        long l387 = 387;
        int i388 = 388;
        long l388 = 388;
        int i389 = 389;
        long l389 = 389;
        int i390 = 390;
        long l390 = 390;
        int i391 = 391;
        long l391 = 391;
        int i392 = 392;
        long l392 = 392;
        int i393 = 393;
        long l393 = 393;
        int i394 = 394;
        long l394 = 394;
        int i395 = 395;
        long l395 = 395;
        int i396 = 396;
        long l396 = 396;
        int i397 = 397;
        long l397 = 397;
        int i398 = 398;
        long l398 = 398;
        int i399 = 399;
        long l399 = 399;
        int i400 = 400;
        long l400 = 400;
        int i401 = 401;
        long l401 = 401;
        int i402 = 402;
        long l402 = 402;
        int i403 = 403;
        long l403 = 403;
        int i404 = 404;
        long l404 = 404;
        int i405 = 405;
        long l405 = 405;
        int i406 = 406;
        long l406 = 406;
        int i407 = 407;
        long l407 = 407;
        int i408 = 408;
        long l408 = 408;
        int i409 = 409;
        long l409 = 409;
        int i410 = 410;
        long l410 = 410;
        int i411 = 411;
        long l411 = 411;
        int i412 = 412;
        long l412 = 412;
        int i413 = 413;
        long l413 = 413;
        int i414 = 414;
        long l414 = 414;
        int i415 = 415;
        long l415 = 415;
        int i416 = 416;
        long l416 = 416;
        int i417 = 417;
        long l417 = 417;
        int i418 = 418;
        long l418 = 418;
        int i419 = 419;
        long l419 = 419;
        int i420 = 420;
        long l420 = 420;
        int i421 = 421;
        long l421 = 421;
        int i422 = 422;
        long l422 = 422;
        int i423 = 423;
        long l423 = 423;
        int i424 = 424;
        long l424 = 424;
        int i425 = 425;
        long l425 = 425;
        int i426 = 426;
        long l426 = 426;
        int i427 = 427;
        long l427 = 427;
        int i428 = 428;
        long l428 = 428;
        int i429 = 429;
        long l429 = 429;
        int i430 = 430;
        long l430 = 430;
        int i431 = 431;
        long l431 = 431;
        int i432 = 432;
        long l432 = 432;
        int i433 = 433;
        long l433 = 433;
        int i434 = 434;
        long l434 = 434;
        int i435 = 435;
        long l435 = 435;
        int i436 = 436;
        long l436 = 436;
        int i437 = 437;
        long l437 = 437;
        int i438 = 438;
        long l438 = 438;
        int i439 = 439;
        long l439 = 439;
        int i440 = 440;
        long l440 = 440;
        int i441 = 441;
        long l441 = 441;
        int i442 = 442;
        long l442 = 442;
        int i443 = 443;
        long l443 = 443;
        int i444 = 444;
        long l444 = 444;
        int i445 = 445;
        long l445 = 445;
        int i446 = 446;
        long l446 = 446;
        int i447 = 447;
        long l447 = 447;
        int i448 = 448;
        long l448 = 448;
        int i449 = 449;
        long l449 = 449;
        int i450 = 450;
        long l450 = 450;
        int i451 = 451;
        long l451 = 451;
        int i452 = 452;
        long l452 = 452;
        int i453 = 453;
        long l453 = 453;
        int i454 = 454;
        long l454 = 454;
        int i455 = 455;
        long l455 = 455;
        int i456 = 456;
        long l456 = 456;
        int i457 = 457;
        long l457 = 457;
        int i458 = 458;
        long l458 = 458;
        int i459 = 459;
        long l459 = 459;
        int i460 = 460;
        long l460 = 460;
        int i461 = 461;
        long l461 = 461;
        int i462 = 462;
        long l462 = 462;
        int i463 = 463;
        long l463 = 463;
        int i464 = 464;
        long l464 = 464;
        int i465 = 465;
        long l465 = 465;
        int i466 = 466;
        long l466 = 466;
        int i467 = 467;
        long l467 = 467;
        int i468 = 468;
        long l468 = 468;
        int i469 = 469;
        long l469 = 469;
        int i470 = 470;
        long l470 = 470;
        int i471 = 471;
        long l471 = 471;
        int i472 = 472;
        long l472 = 472;
        int i473 = 473;
        long l473 = 473;
        int i474 = 474;
        long l474 = 474;
        int i475 = 475;
        long l475 = 475;
        int i476 = 476;
        long l476 = 476;
        int i477 = 477;
        long l477 = 477;
        int i478 = 478;
        long l478 = 478;
        int i479 = 479;
        long l479 = 479;
        int i480 = 480;
        long l480 = 480;
        int i481 = 481;
        long l481 = 481;
        int i482 = 482;
        long l482 = 482;
        int i483 = 483;
        long l483 = 483;
        int i484 = 484;
        long l484 = 484;
        int i485 = 485;
        long l485 = 485;
        int i486 = 486;
        long l486 = 486;
        int i487 = 487;
        long l487 = 487;
        int i488 = 488;
        long l488 = 488;
        int i489 = 489;
        long l489 = 489;
        int i490 = 490;
        long l490 = 490;
        int i491 = 491;
        long l491 = 491;
        int i492 = 492;
        long l492 = 492;
        int i493 = 493;
        long l493 = 493;
        int i494 = 494;
        long l494 = 494;
        int i495 = 495;
        long l495 = 495;
        int i496 = 496;
        long l496 = 496;
        int i497 = 497;
        long l497 = 497;
        int i498 = 498;
        long l498 = 498;
        int i499 = 499;
        long l499 = 499;
        int i500 = 500;
        long l500 = 500;
        int i501 = 501;
        long l501 = 501;
        int i502 = 502;
        long l502 = 502;
        int i503 = 503;
        long l503 = 503;
        int i504 = 504;
        long l504 = 504;
        int i505 = 505;
        long l505 = 505;
        int i506 = 506;
        long l506 = 506;
        int i507 = 507;
        long l507 = 507;
        int i508 = 508;
        long l508 = 508;
        int i509 = 509;
        long l509 = 509;
        int i510 = 510;
        long l510 = 510;
        int i511 = 511;
        long l511 = 511;
        int i512 = 512;
        long l512 = 512;
        int i513 = 513;
        long l513 = 513;
        int i514 = 514;
        long l514 = 514;
        int i515 = 515;
        long l515 = 515;
        int i516 = 516;
        long l516 = 516;
        int i517 = 517;
        long l517 = 517;
        int i518 = 518;
        long l518 = 518;
        int i519 = 519;
        long l519 = 519;
        int i520 = 520;
        long l520 = 520;
        int i521 = 521;
        long l521 = 521;
        int i522 = 522;
        long l522 = 522;
        int i523 = 523;
        long l523 = 523;
        int i524 = 524;
        long l524 = 524;
        int i525 = 525;
        long l525 = 525;
        int i526 = 526;
        long l526 = 526;
        int i527 = 527;
        long l527 = 527;
        int i528 = 528;
        long l528 = 528;
        int i529 = 529;
        long l529 = 529;
        int i530 = 530;
        long l530 = 530;
        int i531 = 531;
        long l531 = 531;
        int i532 = 532;
        long l532 = 532;
        int i533 = 533;
        long l533 = 533;
        int i534 = 534;
        long l534 = 534;
        int i535 = 535;
        long l535 = 535;
        int i536 = 536;
        long l536 = 536;
        int i537 = 537;
        long l537 = 537;
        int i538 = 538;
        long l538 = 538;
        int i539 = 539;
        long l539 = 539;
        int i540 = 540;
        long l540 = 540;
        int i541 = 541;
        long l541 = 541;
        int i542 = 542;
        long l542 = 542;
        int i543 = 543;
        long l543 = 543;
        int i544 = 544;
        long l544 = 544;
        int i545 = 545;
        long l545 = 545;
        int i546 = 546;
        long l546 = 546;
        int i547 = 547;
        long l547 = 547;
        int i548 = 548;
        long l548 = 548;
        int i549 = 549;
        long l549 = 549;
        int i550 = 550;
        long l550 = 550;
        int i551 = 551;
        long l551 = 551;
        int i552 = 552;
        long l552 = 552;
        int i553 = 553;
        long l553 = 553;
        int i554 = 554;
        long l554 = 554;
        int i555 = 555;
        long l555 = 555;
        int i556 = 556;
        long l556 = 556;
        int i557 = 557;
        long l557 = 557;
        int i558 = 558;
        long l558 = 558;
        int i559 = 559;
        long l559 = 559;
        int i560 = 560;
        long l560 = 560;
        int i561 = 561;
        long l561 = 561;
        int i562 = 562;
        long l562 = 562;
        int i563 = 563;
        long l563 = 563;
        int i564 = 564;
        long l564 = 564;
        int i565 = 565;
        long l565 = 565;
        int i566 = 566;
        long l566 = 566;
        int i567 = 567;
        long l567 = 567;
        int i568 = 568;
        long l568 = 568;
        int i569 = 569;
        long l569 = 569;
        int i570 = 570;
        long l570 = 570;
        int i571 = 571;
        long l571 = 571;
        int i572 = 572;
        long l572 = 572;
        int i573 = 573;
        long l573 = 573;
        int i574 = 574;
        long l574 = 574;
        int i575 = 575;
        long l575 = 575;
        int i576 = 576;
        long l576 = 576;
        int i577 = 577;
        long l577 = 577;
        int i578 = 578;
        long l578 = 578;
        int i579 = 579;
        long l579 = 579;
        int i580 = 580;
        long l580 = 580;
        int i581 = 581;
        long l581 = 581;
        int i582 = 582;
        long l582 = 582;
        int i583 = 583;
        long l583 = 583;
        int i584 = 584;
        long l584 = 584;
        int i585 = 585;
        long l585 = 585;
        int i586 = 586;
        long l586 = 586;
        int i587 = 587;
        long l587 = 587;
        int i588 = 588;
        long l588 = 588;
        int i589 = 589;
        long l589 = 589;
        int i590 = 590;
        long l590 = 590;
        int i591 = 591;
        long l591 = 591;
        int i592 = 592;
        long l592 = 592;
        int i593 = 593;
        long l593 = 593;
        int i594 = 594;
        long l594 = 594;
        int i595 = 595;
        long l595 = 595;
        int i596 = 596;
        long l596 = 596;
        int i597 = 597;
        long l597 = 597;
        int i598 = 598;
        long l598 = 598;
        int i599 = 599;
        long l599 = 599;
        int i600 = 600;
        long l600 = 600;
        int i601 = 601;
        long l601 = 601;
        int i602 = 602;
        long l602 = 602;
        int i603 = 603;
        long l603 = 603;
        int i604 = 604;
        long l604 = 604;
        int i605 = 605;
        long l605 = 605;
        int i606 = 606;
        long l606 = 606;
        int i607 = 607;
        long l607 = 607;
        int i608 = 608;
        long l608 = 608;
        int i609 = 609;
        long l609 = 609;
        int i610 = 610;
        long l610 = 610;
        int i611 = 611;
        long l611 = 611;
        int i612 = 612;
        long l612 = 612;
        int i613 = 613;
        long l613 = 613;
        int i614 = 614;
        long l614 = 614;
        int i615 = 615;
        long l615 = 615;
        int i616 = 616;
        long l616 = 616;
        int i617 = 617;
        long l617 = 617;
        int i618 = 618;
        long l618 = 618;
        int i619 = 619;
        long l619 = 619;
        int i620 = 620;
        long l620 = 620;
        int i621 = 621;
        long l621 = 621;
        int i622 = 622;
        long l622 = 622;
        int i623 = 623;
        long l623 = 623;
        int i624 = 624;
        long l624 = 624;
        int i625 = 625;
        long l625 = 625;
        int i626 = 626;
        long l626 = 626;
        int i627 = 627;
        long l627 = 627;
        int i628 = 628;
        long l628 = 628;
        int i629 = 629;
        long l629 = 629;
        int i630 = 630;
        long l630 = 630;
        int i631 = 631;
        long l631 = 631;
        int i632 = 632;
        long l632 = 632;
        int i633 = 633;
        long l633 = 633;
        int i634 = 634;
        long l634 = 634;
        int i635 = 635;
        long l635 = 635;
        int i636 = 636;
        long l636 = 636;
        int i637 = 637;
        long l637 = 637;
        int i638 = 638;
        long l638 = 638;
        int i639 = 639;
        long l639 = 639;
        int i640 = 640;
        long l640 = 640;
        int i641 = 641;
        long l641 = 641;
        int i642 = 642;
        long l642 = 642;
        int i643 = 643;
        long l643 = 643;
        int i644 = 644;
        long l644 = 644;
        int i645 = 645;
        long l645 = 645;
        int i646 = 646;
        long l646 = 646;
        int i647 = 647;
        long l647 = 647;
        int i648 = 648;
        long l648 = 648;
        int i649 = 649;
        long l649 = 649;
        int i650 = 650;
        long l650 = 650;
        int i651 = 651;
        long l651 = 651;
        int i652 = 652;
        long l652 = 652;
        int i653 = 653;
        long l653 = 653;
        int i654 = 654;
        long l654 = 654;
        int i655 = 655;
        long l655 = 655;
        int i656 = 656;
        long l656 = 656;
        int i657 = 657;
        long l657 = 657;
        int i658 = 658;
        long l658 = 658;
        int i659 = 659;
        long l659 = 659;
        int i660 = 660;
        long l660 = 660;
        int i661 = 661;
        long l661 = 661;
        int i662 = 662;
        long l662 = 662;
        int i663 = 663;
        long l663 = 663;
        int i664 = 664;
        long l664 = 664;
        int i665 = 665;
        long l665 = 665;
        int i666 = 666;
        long l666 = 666;
        int i667 = 667;
        long l667 = 667;
        int i668 = 668;
        long l668 = 668;
        int i669 = 669;
        long l669 = 669;
        int i670 = 670;
        long l670 = 670;
        int i671 = 671;
        long l671 = 671;
        int i672 = 672;
        long l672 = 672;
        int i673 = 673;
        long l673 = 673;
        int i674 = 674;
        long l674 = 674;
        int i675 = 675;
        long l675 = 675;
        int i676 = 676;
        long l676 = 676;
        int i677 = 677;
        long l677 = 677;
        int i678 = 678;
        long l678 = 678;
        int i679 = 679;
        long l679 = 679;
        int i680 = 680;
        long l680 = 680;
        int i681 = 681;
        long l681 = 681;
        int i682 = 682;
        long l682 = 682;
        int i683 = 683;
        long l683 = 683;
        int i684 = 684;
        long l684 = 684;
        int i685 = 685;
        long l685 = 685;
        int i686 = 686;
        long l686 = 686;
        int i687 = 687;
        long l687 = 687;
        int i688 = 688;
        long l688 = 688;
        int i689 = 689;
        long l689 = 689;
        int i690 = 690;
        long l690 = 690;
        int i691 = 691;
        long l691 = 691;
        int i692 = 692;
        long l692 = 692;
        int i693 = 693;
        long l693 = 693;
        int i694 = 694;
        long l694 = 694;
        int i695 = 695;
        long l695 = 695;
        int i696 = 696;
        long l696 = 696;
        int i697 = 697;
        long l697 = 697;
        int i698 = 698;
        long l698 = 698;
        int i699 = 699;
        long l699 = 699;
        int i700 = 700;
        long l700 = 700;
        int i701 = 701;
        long l701 = 701;
        int i702 = 702;
        long l702 = 702;
        int i703 = 703;
        long l703 = 703;
        int i704 = 704;
        long l704 = 704;
        int i705 = 705;
        long l705 = 705;
        int i706 = 706;
        long l706 = 706;
        int i707 = 707;
        long l707 = 707;
        int i708 = 708;
        long l708 = 708;
        int i709 = 709;
        long l709 = 709;
        int i710 = 710;
        long l710 = 710;
        int i711 = 711;
        long l711 = 711;
        int i712 = 712;
        long l712 = 712;
        int i713 = 713;
        long l713 = 713;
        int i714 = 714;
        long l714 = 714;
        int i715 = 715;
        long l715 = 715;
        int i716 = 716;
        long l716 = 716;
        int i717 = 717;
        long l717 = 717;
        int i718 = 718;
        long l718 = 718;
        int i719 = 719;
        long l719 = 719;
        int i720 = 720;
        long l720 = 720;
        int i721 = 721;
        long l721 = 721;
        int i722 = 722;
        long l722 = 722;
        int i723 = 723;
        long l723 = 723;
        int i724 = 724;
        long l724 = 724;
        int i725 = 725;
        long l725 = 725;
        int i726 = 726;
        long l726 = 726;
        int i727 = 727;
        long l727 = 727;
        int i728 = 728;
        long l728 = 728;
        int i729 = 729;
        long l729 = 729;
        int i730 = 730;
        long l730 = 730;
        int i731 = 731;
        long l731 = 731;
        int i732 = 732;
        long l732 = 732;
        int i733 = 733;
        long l733 = 733;
        int i734 = 734;
        long l734 = 734;
        int i735 = 735;
        long l735 = 735;
        int i736 = 736;
        long l736 = 736;
        int i737 = 737;
        long l737 = 737;
        int i738 = 738;
        long l738 = 738;
        int i739 = 739;
        long l739 = 739;
        int i740 = 740;
        long l740 = 740;
        int i741 = 741;
        long l741 = 741;
        int i742 = 742;
        long l742 = 742;
        int i743 = 743;
        long l743 = 743;
        int i744 = 744;
        long l744 = 744;
        int i745 = 745;
        long l745 = 745;
        int i746 = 746;
        long l746 = 746;
        int i747 = 747;
        long l747 = 747;
        int i748 = 748;
        long l748 = 748;
        int i749 = 749;
        long l749 = 749;
        int i750 = 750;
        long l750 = 750;
        int i751 = 751;
        long l751 = 751;
        int i752 = 752;
        long l752 = 752;
        int i753 = 753;
        long l753 = 753;
        int i754 = 754;
        long l754 = 754;
        int i755 = 755;
        long l755 = 755;
        int i756 = 756;
        long l756 = 756;
        int i757 = 757;
        long l757 = 757;
        int i758 = 758;
        long l758 = 758;
        int i759 = 759;
        long l759 = 759;
        int i760 = 760;
        long l760 = 760;
        int i761 = 761;
        long l761 = 761;
        int i762 = 762;
        long l762 = 762;
        int i763 = 763;
        long l763 = 763;
        int i764 = 764;
        long l764 = 764;
        int i765 = 765;
        long l765 = 765;
        int i766 = 766;
        long l766 = 766;
        int i767 = 767;
        long l767 = 767;
        int i768 = 768;
        long l768 = 768;
        int i769 = 769;
        long l769 = 769;
        int i770 = 770;
        long l770 = 770;
        int i771 = 771;
        long l771 = 771;
        int i772 = 772;
        long l772 = 772;
        int i773 = 773;
        long l773 = 773;
        int i774 = 774;
        long l774 = 774;
        int i775 = 775;
        long l775 = 775;
        int i776 = 776;
        long l776 = 776;
        int i777 = 777;
        long l777 = 777;
        int i778 = 778;
        long l778 = 778;
        int i779 = 779;
        long l779 = 779;
        int i780 = 780;
        long l780 = 780;
        int i781 = 781;
        long l781 = 781;
        int i782 = 782;
        long l782 = 782;
        int i783 = 783;
        long l783 = 783;
        int i784 = 784;
        long l784 = 784;
        int i785 = 785;
        long l785 = 785;
        int i786 = 786;
        long l786 = 786;
        int i787 = 787;
        long l787 = 787;
        int i788 = 788;
        long l788 = 788;
        int i789 = 789;
        long l789 = 789;
        int i790 = 790;
        long l790 = 790;
        int i791 = 791;
        long l791 = 791;
        int i792 = 792;
        long l792 = 792;
        int i793 = 793;
        long l793 = 793;
        int i794 = 794;
        long l794 = 794;
        int i795 = 795;
        long l795 = 795;
        int i796 = 796;
        long l796 = 796;
        int i797 = 797;
        long l797 = 797;
        int i798 = 798;
        long l798 = 798;
        int i799 = 799;
        long l799 = 799;
        int i800 = 800;
        long l800 = 800;
        int i801 = 801;
        long l801 = 801;
        int i802 = 802;
        long l802 = 802;
        int i803 = 803;
        long l803 = 803;
        int i804 = 804;
        long l804 = 804;
        int i805 = 805;
        long l805 = 805;
        int i806 = 806;
        long l806 = 806;
        int i807 = 807;
        long l807 = 807;
        int i808 = 808;
        long l808 = 808;
        int i809 = 809;
        long l809 = 809;
        int i810 = 810;
        long l810 = 810;
        int i811 = 811;
        long l811 = 811;
        int i812 = 812;
        long l812 = 812;
        int i813 = 813;
        long l813 = 813;
        int i814 = 814;
        long l814 = 814;
        int i815 = 815;
        long l815 = 815;
        int i816 = 816;
        long l816 = 816;
        int i817 = 817;
        long l817 = 817;
        int i818 = 818;
        long l818 = 818;
        int i819 = 819;
        long l819 = 819;
        int i820 = 820;
        long l820 = 820;
        int i821 = 821;
        long l821 = 821;
        int i822 = 822;
        long l822 = 822;
        int i823 = 823;
        long l823 = 823;
        int i824 = 824;
        long l824 = 824;
        int i825 = 825;
        long l825 = 825;
        int i826 = 826;
        long l826 = 826;
        int i827 = 827;
        long l827 = 827;
        int i828 = 828;
        long l828 = 828;
        int i829 = 829;
        long l829 = 829;
        int i830 = 830;
        long l830 = 830;
        int i831 = 831;
        long l831 = 831;
        int i832 = 832;
        long l832 = 832;
        int i833 = 833;
        long l833 = 833;
        int i834 = 834;
        long l834 = 834;
        int i835 = 835;
        long l835 = 835;
        int i836 = 836;
        long l836 = 836;
        int i837 = 837;
        long l837 = 837;
        int i838 = 838;
        long l838 = 838;
        int i839 = 839;
        long l839 = 839;
        int i840 = 840;
        long l840 = 840;
        int i841 = 841;
        long l841 = 841;
        int i842 = 842;
        long l842 = 842;
        int i843 = 843;
        long l843 = 843;
        int i844 = 844;
        long l844 = 844;
        int i845 = 845;
        long l845 = 845;
        int i846 = 846;
        long l846 = 846;
        int i847 = 847;
        long l847 = 847;
        int i848 = 848;
        long l848 = 848;
        int i849 = 849;
        long l849 = 849;
        int i850 = 850;
        long l850 = 850;
        int i851 = 851;
        long l851 = 851;
        int i852 = 852;
        long l852 = 852;
        int i853 = 853;
        long l853 = 853;
        int i854 = 854;
        long l854 = 854;
        int i855 = 855;
        long l855 = 855;
        int i856 = 856;
        long l856 = 856;
        int i857 = 857;
        long l857 = 857;
        int i858 = 858;
        long l858 = 858;
        int i859 = 859;
        long l859 = 859;
        int i860 = 860;
        long l860 = 860;
        int i861 = 861;
        long l861 = 861;
        int i862 = 862;
        long l862 = 862;
        int i863 = 863;
        long l863 = 863;
        int i864 = 864;
        long l864 = 864;
        int i865 = 865;
        long l865 = 865;
        int i866 = 866;
        long l866 = 866;
        int i867 = 867;
        long l867 = 867;
        int i868 = 868;
        long l868 = 868;
        int i869 = 869;
        long l869 = 869;
        int i870 = 870;
        long l870 = 870;
        int i871 = 871;
        long l871 = 871;
        int i872 = 872;
        long l872 = 872;
        int i873 = 873;
        long l873 = 873;
        int i874 = 874;
        long l874 = 874;
        int i875 = 875;
        long l875 = 875;
        int i876 = 876;
        long l876 = 876;
        int i877 = 877;
        long l877 = 877;
        int i878 = 878;
        long l878 = 878;
        int i879 = 879;
        long l879 = 879;
        int i880 = 880;
        long l880 = 880;
        int i881 = 881;
        long l881 = 881;
        int i882 = 882;
        long l882 = 882;
        int i883 = 883;
        long l883 = 883;
        int i884 = 884;
        long l884 = 884;
        int i885 = 885;
        long l885 = 885;
        int i886 = 886;
        long l886 = 886;
        int i887 = 887;
        long l887 = 887;
        int i888 = 888;
        long l888 = 888;
        int i889 = 889;
        long l889 = 889;
        int i890 = 890;
        long l890 = 890;
        int i891 = 891;
        long l891 = 891;
        int i892 = 892;
        long l892 = 892;
        int i893 = 893;
        long l893 = 893;
        int i894 = 894;
        long l894 = 894;
        int i895 = 895;
        long l895 = 895;
        int i896 = 896;
        long l896 = 896;
        int i897 = 897;
        long l897 = 897;
        int i898 = 898;
        long l898 = 898;
        int i899 = 899;
        long l899 = 899;
        int i900 = 900;
        long l900 = 900;
        int i901 = 901;
        long l901 = 901;
        int i902 = 902;
        long l902 = 902;
        int i903 = 903;
        long l903 = 903;
        int i904 = 904;
        long l904 = 904;
        int i905 = 905;
        long l905 = 905;
        int i906 = 906;
        long l906 = 906;
        int i907 = 907;
        long l907 = 907;
        int i908 = 908;
        long l908 = 908;
        int i909 = 909;
        long l909 = 909;
        int i910 = 910;
        long l910 = 910;
        int i911 = 911;
        long l911 = 911;
        int i912 = 912;
        long l912 = 912;
        int i913 = 913;
        long l913 = 913;
        int i914 = 914;
        long l914 = 914;
        int i915 = 915;
        long l915 = 915;
        int i916 = 916;
        long l916 = 916;
        int i917 = 917;
        long l917 = 917;
        int i918 = 918;
        long l918 = 918;
        int i919 = 919;
        long l919 = 919;
        int i920 = 920;
        long l920 = 920;
        int i921 = 921;
        long l921 = 921;
        int i922 = 922;
        long l922 = 922;
        int i923 = 923;
        long l923 = 923;
        int i924 = 924;
        long l924 = 924;
        int i925 = 925;
        long l925 = 925;
        int i926 = 926;
        long l926 = 926;
        int i927 = 927;
        long l927 = 927;
        int i928 = 928;
        long l928 = 928;
        int i929 = 929;
        long l929 = 929;
        int i930 = 930;
        long l930 = 930;
        int i931 = 931;
        long l931 = 931;
        int i932 = 932;
        long l932 = 932;
        int i933 = 933;
        long l933 = 933;
        int i934 = 934;
        long l934 = 934;
        int i935 = 935;
        long l935 = 935;
        int i936 = 936;
        long l936 = 936;
        int i937 = 937;
        long l937 = 937;
        int i938 = 938;
        long l938 = 938;
        int i939 = 939;
        long l939 = 939;
        int i940 = 940;
        long l940 = 940;
        int i941 = 941;
        long l941 = 941;
        int i942 = 942;
        long l942 = 942;
        int i943 = 943;
        long l943 = 943;
        int i944 = 944;
        long l944 = 944;
        int i945 = 945;
        long l945 = 945;
        int i946 = 946;
        long l946 = 946;
        int i947 = 947;
        long l947 = 947;
        int i948 = 948;
        long l948 = 948;
        int i949 = 949;
        long l949 = 949;
        int i950 = 950;
        long l950 = 950;
        int i951 = 951;
        long l951 = 951;
        int i952 = 952;
        long l952 = 952;
        int i953 = 953;
        long l953 = 953;
        int i954 = 954;
        long l954 = 954;
        int i955 = 955;
        long l955 = 955;
        int i956 = 956;
        long l956 = 956;
        int i957 = 957;
        long l957 = 957;
        int i958 = 958;
        long l958 = 958;
        int i959 = 959;
        long l959 = 959;
        int i960 = 960;
        long l960 = 960;
        int i961 = 961;
        long l961 = 961;
        int i962 = 962;
        long l962 = 962;
        int i963 = 963;
        long l963 = 963;
        int i964 = 964;
        long l964 = 964;
        int i965 = 965;
        long l965 = 965;
        int i966 = 966;
        long l966 = 966;
        int i967 = 967;
        long l967 = 967;
        int i968 = 968;
        long l968 = 968;
        int i969 = 969;
        long l969 = 969;
        int i970 = 970;
        long l970 = 970;
        int i971 = 971;
        long l971 = 971;
        int i972 = 972;
        long l972 = 972;
        int i973 = 973;
        long l973 = 973;
        int i974 = 974;
        long l974 = 974;
        int i975 = 975;
        long l975 = 975;
        int i976 = 976;
        long l976 = 976;
        int i977 = 977;
        long l977 = 977;
        int i978 = 978;
        long l978 = 978;
        int i979 = 979;
        long l979 = 979;
        int i980 = 980;
        long l980 = 980;
        int i981 = 981;
        long l981 = 981;
        int i982 = 982;
        long l982 = 982;
        int i983 = 983;
        long l983 = 983;
        int i984 = 984;
        long l984 = 984;
        int i985 = 985;
        long l985 = 985;
        int i986 = 986;
        long l986 = 986;
        int i987 = 987;
        long l987 = 987;
        int i988 = 988;
        long l988 = 988;
        int i989 = 989;
        long l989 = 989;
        int i990 = 990;
        long l990 = 990;
        int i991 = 991;
        long l991 = 991;
        int i992 = 992;
        long l992 = 992;
        int i993 = 993;
        long l993 = 993;
        int i994 = 994;
        long l994 = 994;
        int i995 = 995;
        long l995 = 995;
        int i996 = 996;
        long l996 = 996;
        int i997 = 997;
        long l997 = 997;
        int i998 = 998;
        long l998 = 998;
        int i999 = 999;
        long l999 = 999;
        i1 += i0;
        l1 = l0;
        i2 += i1;
        l2 = l1;
        i3 += i2;
        l3 = l2;
        i4 += i3;
        l4 = l3;
        i5 += i4;
        l5 = l4;
        i6 += i5;
        l6 = l5;
        i7 += i6;
        l7 = l6;
        i8 += i7;
        l8 = l7;
        i9 += i8;
        l9 = l8;
        i10 += i9;
        l10 = l9;
        i11 += i10;
        l11 = l10;
        i12 += i11;
        l12 = l11;
        i13 += i12;
        l13 = l12;
        i14 += i13;
        l14 = l13;
        i15 += i14;
        l15 = l14;
        i16 += i15;
        l16 = l15;
        i17 += i16;
        l17 = l16;
        i18 += i17;
        l18 = l17;
        i19 += i18;
        l19 = l18;
        i20 += i19;
        l20 = l19;
        i21 += i20;
        l21 = l20;
        i22 += i21;
        l22 = l21;
        i23 += i22;
        l23 = l22;
        i24 += i23;
        l24 = l23;
        i25 += i24;
        l25 = l24;
        i26 += i25;
        l26 = l25;
        i27 += i26;
        l27 = l26;
        i28 += i27;
        l28 = l27;
        i29 += i28;
        l29 = l28;
        i30 += i29;
        l30 = l29;
        i31 += i30;
        l31 = l30;
        i32 += i31;
        l32 = l31;
        i33 += i32;
        l33 = l32;
        i34 += i33;
        l34 = l33;
        i35 += i34;
        l35 = l34;
        i36 += i35;
        l36 = l35;
        i37 += i36;
        l37 = l36;
        i38 += i37;
        l38 = l37;
        i39 += i38;
        l39 = l38;
        i40 += i39;
        l40 = l39;
        i41 += i40;
        l41 = l40;
        i42 += i41;
        l42 = l41;
        i43 += i42;
        l43 = l42;
        i44 += i43;
        l44 = l43;
        i45 += i44;
        l45 = l44;
        i46 += i45;
        l46 = l45;
        i47 += i46;
        l47 = l46;
        i48 += i47;
        l48 = l47;
        i49 += i48;
        l49 = l48;
        i50 += i49;
        l50 = l49;
        i51 += i50;
        l51 = l50;
        i52 += i51;
        l52 = l51;
        i53 += i52;
        l53 = l52;
        i54 += i53;
        l54 = l53;
        i55 += i54;
        l55 = l54;
        i56 += i55;
        l56 = l55;
        i57 += i56;
        l57 = l56;
        i58 += i57;
        l58 = l57;
        i59 += i58;
        l59 = l58;
        i60 += i59;
        l60 = l59;
        i61 += i60;
        l61 = l60;
        i62 += i61;
        l62 = l61;
        i63 += i62;
        l63 = l62;
        i64 += i63;
        l64 = l63;
        i65 += i64;
        l65 = l64;
        i66 += i65;
        l66 = l65;
        i67 += i66;
        l67 = l66;
        i68 += i67;
        l68 = l67;
        i69 += i68;
        l69 = l68;
        i70 += i69;
        l70 = l69;
        i71 += i70;
        l71 = l70;
        i72 += i71;
        l72 = l71;
        i73 += i72;
        l73 = l72;
        i74 += i73;
        l74 = l73;
        i75 += i74;
        l75 = l74;
        i76 += i75;
        l76 = l75;
        i77 += i76;
        l77 = l76;
        i78 += i77;
        l78 = l77;
        i79 += i78;
        l79 = l78;
        i80 += i79;
        l80 = l79;
        i81 += i80;
        l81 = l80;
        i82 += i81;
        l82 = l81;
        i83 += i82;
        l83 = l82;
        i84 += i83;
        l84 = l83;
        i85 += i84;
        l85 = l84;
        i86 += i85;
        l86 = l85;
        i87 += i86;
        l87 = l86;
        i88 += i87;
        l88 = l87;
        i89 += i88;
        l89 = l88;
        i90 += i89;
        l90 = l89;
        i91 += i90;
        l91 = l90;
        i92 += i91;
        l92 = l91;
        i93 += i92;
        l93 = l92;
        i94 += i93;
        l94 = l93;
        i95 += i94;
        l95 = l94;
        i96 += i95;
        l96 = l95;
        i97 += i96;
        l97 = l96;
        i98 += i97;
        l98 = l97;
        i99 += i98;
        l99 = l98;
        i100 += i99;
        l100 = l99;
        i101 += i100;
        l101 = l100;
        i102 += i101;
        l102 = l101;
        i103 += i102;
        l103 = l102;
        i104 += i103;
        l104 = l103;
        i105 += i104;
        l105 = l104;
        i106 += i105;
        l106 = l105;
        i107 += i106;
        l107 = l106;
        i108 += i107;
        l108 = l107;
        i109 += i108;
        l109 = l108;
        i110 += i109;
        l110 = l109;
        i111 += i110;
        l111 = l110;
        i112 += i111;
        l112 = l111;
        i113 += i112;
        l113 = l112;
        i114 += i113;
        l114 = l113;
        i115 += i114;
        l115 = l114;
        i116 += i115;
        l116 = l115;
        i117 += i116;
        l117 = l116;
        i118 += i117;
        l118 = l117;
        i119 += i118;
        l119 = l118;
        i120 += i119;
        l120 = l119;
        i121 += i120;
        l121 = l120;
        i122 += i121;
        l122 = l121;
        i123 += i122;
        l123 = l122;
        i124 += i123;
        l124 = l123;
        i125 += i124;
        l125 = l124;
        i126 += i125;
        l126 = l125;
        i127 += i126;
        l127 = l126;
        i128 += i127;
        l128 = l127;
        i129 += i128;
        l129 = l128;
        i130 += i129;
        l130 = l129;
        i131 += i130;
        l131 = l130;
        i132 += i131;
        l132 = l131;
        i133 += i132;
        l133 = l132;
        i134 += i133;
        l134 = l133;
        i135 += i134;
        l135 = l134;
        i136 += i135;
        l136 = l135;
        i137 += i136;
        l137 = l136;
        i138 += i137;
        l138 = l137;
        i139 += i138;
        l139 = l138;
        i140 += i139;
        l140 = l139;
        i141 += i140;
        l141 = l140;
        i142 += i141;
        l142 = l141;
        i143 += i142;
        l143 = l142;
        i144 += i143;
        l144 = l143;
        i145 += i144;
        l145 = l144;
        i146 += i145;
        l146 = l145;
        i147 += i146;
        l147 = l146;
        i148 += i147;
        l148 = l147;
        i149 += i148;
        l149 = l148;
        i150 += i149;
        l150 = l149;
        i151 += i150;
        l151 = l150;
        i152 += i151;
        l152 = l151;
        i153 += i152;
        l153 = l152;
        i154 += i153;
        l154 = l153;
        i155 += i154;
        l155 = l154;
        i156 += i155;
        l156 = l155;
        i157 += i156;
        l157 = l156;
        i158 += i157;
        l158 = l157;
        i159 += i158;
        l159 = l158;
        i160 += i159;
        l160 = l159;
        i161 += i160;
        l161 = l160;
        i162 += i161;
        l162 = l161;
        i163 += i162;
        l163 = l162;
        i164 += i163;
        l164 = l163;
        i165 += i164;
        l165 = l164;
        i166 += i165;
        l166 = l165;
        i167 += i166;
        l167 = l166;
        i168 += i167;
        l168 = l167;
        i169 += i168;
        l169 = l168;
        i170 += i169;
        l170 = l169;
        i171 += i170;
        l171 = l170;
        i172 += i171;
        l172 = l171;
        i173 += i172;
        l173 = l172;
        i174 += i173;
        l174 = l173;
        i175 += i174;
        l175 = l174;
        i176 += i175;
        l176 = l175;
        i177 += i176;
        l177 = l176;
        i178 += i177;
        l178 = l177;
        i179 += i178;
        l179 = l178;
        i180 += i179;
        l180 = l179;
        i181 += i180;
        l181 = l180;
        i182 += i181;
        l182 = l181;
        i183 += i182;
        l183 = l182;
        i184 += i183;
        l184 = l183;
        i185 += i184;
        l185 = l184;
        i186 += i185;
        l186 = l185;
        i187 += i186;
        l187 = l186;
        i188 += i187;
        l188 = l187;
        i189 += i188;
        l189 = l188;
        i190 += i189;
        l190 = l189;
        i191 += i190;
        l191 = l190;
        i192 += i191;
        l192 = l191;
        i193 += i192;
        l193 = l192;
        i194 += i193;
        l194 = l193;
        i195 += i194;
        l195 = l194;
        i196 += i195;
        l196 = l195;
        i197 += i196;
        l197 = l196;
        i198 += i197;
        l198 = l197;
        i199 += i198;
        l199 = l198;
        i200 += i199;
        l200 = l199;
        i201 += i200;
        l201 = l200;
        i202 += i201;
        l202 = l201;
        i203 += i202;
        l203 = l202;
        i204 += i203;
        l204 = l203;
        i205 += i204;
        l205 = l204;
        i206 += i205;
        l206 = l205;
        i207 += i206;
        l207 = l206;
        i208 += i207;
        l208 = l207;
        i209 += i208;
        l209 = l208;
        i210 += i209;
        l210 = l209;
        i211 += i210;
        l211 = l210;
        i212 += i211;
        l212 = l211;
        i213 += i212;
        l213 = l212;
        i214 += i213;
        l214 = l213;
        i215 += i214;
        l215 = l214;
        i216 += i215;
        l216 = l215;
        i217 += i216;
        l217 = l216;
        i218 += i217;
        l218 = l217;
        i219 += i218;
        l219 = l218;
        i220 += i219;
        l220 = l219;
        i221 += i220;
        l221 = l220;
        i222 += i221;
        l222 = l221;
        i223 += i222;
        l223 = l222;
        i224 += i223;
        l224 = l223;
        i225 += i224;
        l225 = l224;
        i226 += i225;
        l226 = l225;
        i227 += i226;
        l227 = l226;
        i228 += i227;
        l228 = l227;
        i229 += i228;
        l229 = l228;
        i230 += i229;
        l230 = l229;
        i231 += i230;
        l231 = l230;
        i232 += i231;
        l232 = l231;
        i233 += i232;
        l233 = l232;
        i234 += i233;
        l234 = l233;
        i235 += i234;
        l235 = l234;
        i236 += i235;
        l236 = l235;
        i237 += i236;
        l237 = l236;
        i238 += i237;
        l238 = l237;
        i239 += i238;
        l239 = l238;
        i240 += i239;
        l240 = l239;
        i241 += i240;
        l241 = l240;
        i242 += i241;
        l242 = l241;
        i243 += i242;
        l243 = l242;
        i244 += i243;
        l244 = l243;
        i245 += i244;
        l245 = l244;
        i246 += i245;
        l246 = l245;
        i247 += i246;
        l247 = l246;
        i248 += i247;
        l248 = l247;
        i249 += i248;
        l249 = l248;
        i250 += i249;
        l250 = l249;
        i251 += i250;
        l251 = l250;
        i252 += i251;
        l252 = l251;
        i253 += i252;
        l253 = l252;
        i254 += i253;
        l254 = l253;
        i255 += i254;
        l255 = l254;
        i256 += i255;
        l256 = l255;
        i257 += i256;
        l257 = l256;
        i258 += i257;
        l258 = l257;
        i259 += i258;
        l259 = l258;
        i260 += i259;
        l260 = l259;
        i261 += i260;
        l261 = l260;
        i262 += i261;
        l262 = l261;
        i263 += i262;
        l263 = l262;
        i264 += i263;
        l264 = l263;
        i265 += i264;
        l265 = l264;
        i266 += i265;
        l266 = l265;
        i267 += i266;
        l267 = l266;
        i268 += i267;
        l268 = l267;
        i269 += i268;
        l269 = l268;
        i270 += i269;
        l270 = l269;
        i271 += i270;
        l271 = l270;
        i272 += i271;
        l272 = l271;
        i273 += i272;
        l273 = l272;
        i274 += i273;
        l274 = l273;
        i275 += i274;
        l275 = l274;
        i276 += i275;
        l276 = l275;
        i277 += i276;
        l277 = l276;
        i278 += i277;
        l278 = l277;
        i279 += i278;
        l279 = l278;
        i280 += i279;
        l280 = l279;
        i281 += i280;
        l281 = l280;
        i282 += i281;
        l282 = l281;
        i283 += i282;
        l283 = l282;
        i284 += i283;
        l284 = l283;
        i285 += i284;
        l285 = l284;
        i286 += i285;
        l286 = l285;
        i287 += i286;
        l287 = l286;
        i288 += i287;
        l288 = l287;
        i289 += i288;
        l289 = l288;
        i290 += i289;
        l290 = l289;
        i291 += i290;
        l291 = l290;
        i292 += i291;
        l292 = l291;
        i293 += i292;
        l293 = l292;
        i294 += i293;
        l294 = l293;
        i295 += i294;
        l295 = l294;
        i296 += i295;
        l296 = l295;
        i297 += i296;
        l297 = l296;
        i298 += i297;
        l298 = l297;
        i299 += i298;
        l299 = l298;
        i300 += i299;
        l300 = l299;
        i301 += i300;
        l301 = l300;
        i302 += i301;
        l302 = l301;
        i303 += i302;
        l303 = l302;
        i304 += i303;
        l304 = l303;
        i305 += i304;
        l305 = l304;
        i306 += i305;
        l306 = l305;
        i307 += i306;
        l307 = l306;
        i308 += i307;
        l308 = l307;
        i309 += i308;
        l309 = l308;
        i310 += i309;
        l310 = l309;
        i311 += i310;
        l311 = l310;
        i312 += i311;
        l312 = l311;
        i313 += i312;
        l313 = l312;
        i314 += i313;
        l314 = l313;
        i315 += i314;
        l315 = l314;
        i316 += i315;
        l316 = l315;
        i317 += i316;
        l317 = l316;
        i318 += i317;
        l318 = l317;
        i319 += i318;
        l319 = l318;
        i320 += i319;
        l320 = l319;
        i321 += i320;
        l321 = l320;
        i322 += i321;
        l322 = l321;
        i323 += i322;
        l323 = l322;
        i324 += i323;
        l324 = l323;
        i325 += i324;
        l325 = l324;
        i326 += i325;
        l326 = l325;
        i327 += i326;
        l327 = l326;
        i328 += i327;
        l328 = l327;
        i329 += i328;
        l329 = l328;
        i330 += i329;
        l330 = l329;
        i331 += i330;
        l331 = l330;
        i332 += i331;
        l332 = l331;
        i333 += i332;
        l333 = l332;
        i334 += i333;
        l334 = l333;
        i335 += i334;
        l335 = l334;
        i336 += i335;
        l336 = l335;
        i337 += i336;
        l337 = l336;
        i338 += i337;
        l338 = l337;
        i339 += i338;
        l339 = l338;
        i340 += i339;
        l340 = l339;
        i341 += i340;
        l341 = l340;
        i342 += i341;
        l342 = l341;
        i343 += i342;
        l343 = l342;
        i344 += i343;
        l344 = l343;
        i345 += i344;
        l345 = l344;
        i346 += i345;
        l346 = l345;
        i347 += i346;
        l347 = l346;
        i348 += i347;
        l348 = l347;
        i349 += i348;
        l349 = l348;
        i350 += i349;
        l350 = l349;
        i351 += i350;
        l351 = l350;
        i352 += i351;
        l352 = l351;
        i353 += i352;
        l353 = l352;
        i354 += i353;
        l354 = l353;
        i355 += i354;
        l355 = l354;
        i356 += i355;
        l356 = l355;
        i357 += i356;
        l357 = l356;
        i358 += i357;
        l358 = l357;
        i359 += i358;
        l359 = l358;
        i360 += i359;
        l360 = l359;
        i361 += i360;
        l361 = l360;
        i362 += i361;
        l362 = l361;
        i363 += i362;
        l363 = l362;
        i364 += i363;
        l364 = l363;
        i365 += i364;
        l365 = l364;
        i366 += i365;
        l366 = l365;
        i367 += i366;
        l367 = l366;
        i368 += i367;
        l368 = l367;
        i369 += i368;
        l369 = l368;
        i370 += i369;
        l370 = l369;
        i371 += i370;
        l371 = l370;
        i372 += i371;
        l372 = l371;
        i373 += i372;
        l373 = l372;
        i374 += i373;
        l374 = l373;
        i375 += i374;
        l375 = l374;
        i376 += i375;
        l376 = l375;
        i377 += i376;
        l377 = l376;
        i378 += i377;
        l378 = l377;
        i379 += i378;
        l379 = l378;
        i380 += i379;
        l380 = l379;
        i381 += i380;
        l381 = l380;
        i382 += i381;
        l382 = l381;
        i383 += i382;
        l383 = l382;
        i384 += i383;
        l384 = l383;
        i385 += i384;
        l385 = l384;
        i386 += i385;
        l386 = l385;
        i387 += i386;
        l387 = l386;
        i388 += i387;
        l388 = l387;
        i389 += i388;
        l389 = l388;
        i390 += i389;
        l390 = l389;
        i391 += i390;
        l391 = l390;
        i392 += i391;
        l392 = l391;
        i393 += i392;
        l393 = l392;
        i394 += i393;
        l394 = l393;
        i395 += i394;
        l395 = l394;
        i396 += i395;
        l396 = l395;
        i397 += i396;
        l397 = l396;
        i398 += i397;
        l398 = l397;
        i399 += i398;
        l399 = l398;
        i400 += i399;
        l400 = l399;
        i401 += i400;
        l401 = l400;
        i402 += i401;
        l402 = l401;
        i403 += i402;
        l403 = l402;
        i404 += i403;
        l404 = l403;
        i405 += i404;
        l405 = l404;
        i406 += i405;
        l406 = l405;
        i407 += i406;
        l407 = l406;
        i408 += i407;
        l408 = l407;
        i409 += i408;
        l409 = l408;
        i410 += i409;
        l410 = l409;
        i411 += i410;
        l411 = l410;
        i412 += i411;
        l412 = l411;
        i413 += i412;
        l413 = l412;
        i414 += i413;
        l414 = l413;
        i415 += i414;
        l415 = l414;
        i416 += i415;
        l416 = l415;
        i417 += i416;
        l417 = l416;
        i418 += i417;
        l418 = l417;
        i419 += i418;
        l419 = l418;
        i420 += i419;
        l420 = l419;
        i421 += i420;
        l421 = l420;
        i422 += i421;
        l422 = l421;
        i423 += i422;
        l423 = l422;
        i424 += i423;
        l424 = l423;
        i425 += i424;
        l425 = l424;
        i426 += i425;
        l426 = l425;
        i427 += i426;
        l427 = l426;
        i428 += i427;
        l428 = l427;
        i429 += i428;
        l429 = l428;
        i430 += i429;
        l430 = l429;
        i431 += i430;
        l431 = l430;
        i432 += i431;
        l432 = l431;
        i433 += i432;
        l433 = l432;
        i434 += i433;
        l434 = l433;
        i435 += i434;
        l435 = l434;
        i436 += i435;
        l436 = l435;
        i437 += i436;
        l437 = l436;
        i438 += i437;
        l438 = l437;
        i439 += i438;
        l439 = l438;
        i440 += i439;
        l440 = l439;
        i441 += i440;
        l441 = l440;
        i442 += i441;
        l442 = l441;
        i443 += i442;
        l443 = l442;
        i444 += i443;
        l444 = l443;
        i445 += i444;
        l445 = l444;
        i446 += i445;
        l446 = l445;
        i447 += i446;
        l447 = l446;
        i448 += i447;
        l448 = l447;
        i449 += i448;
        l449 = l448;
        i450 += i449;
        l450 = l449;
        i451 += i450;
        l451 = l450;
        i452 += i451;
        l452 = l451;
        i453 += i452;
        l453 = l452;
        i454 += i453;
        l454 = l453;
        i455 += i454;
        l455 = l454;
        i456 += i455;
        l456 = l455;
        i457 += i456;
        l457 = l456;
        i458 += i457;
        l458 = l457;
        i459 += i458;
        l459 = l458;
        i460 += i459;
        l460 = l459;
        i461 += i460;
        l461 = l460;
        i462 += i461;
        l462 = l461;
        i463 += i462;
        l463 = l462;
        i464 += i463;
        l464 = l463;
        i465 += i464;
        l465 = l464;
        i466 += i465;
        l466 = l465;
        i467 += i466;
        l467 = l466;
        i468 += i467;
        l468 = l467;
        i469 += i468;
        l469 = l468;
        i470 += i469;
        l470 = l469;
        i471 += i470;
        l471 = l470;
        i472 += i471;
        l472 = l471;
        i473 += i472;
        l473 = l472;
        i474 += i473;
        l474 = l473;
        i475 += i474;
        l475 = l474;
        i476 += i475;
        l476 = l475;
        i477 += i476;
        l477 = l476;
        i478 += i477;
        l478 = l477;
        i479 += i478;
        l479 = l478;
        i480 += i479;
        l480 = l479;
        i481 += i480;
        l481 = l480;
        i482 += i481;
        l482 = l481;
        i483 += i482;
        l483 = l482;
        i484 += i483;
        l484 = l483;
        i485 += i484;
        l485 = l484;
        i486 += i485;
        l486 = l485;
        i487 += i486;
        l487 = l486;
        i488 += i487;
        l488 = l487;
        i489 += i488;
        l489 = l488;
        i490 += i489;
        l490 = l489;
        i491 += i490;
        l491 = l490;
        i492 += i491;
        l492 = l491;
        i493 += i492;
        l493 = l492;
        i494 += i493;
        l494 = l493;
        i495 += i494;
        l495 = l494;
        i496 += i495;
        l496 = l495;
        i497 += i496;
        l497 = l496;
        i498 += i497;
        l498 = l497;
        i499 += i498;
        l499 = l498;
        i500 += i499;
        l500 = l499;
        i501 += i500;
        l501 = l500;
        i502 += i501;
        l502 = l501;
        i503 += i502;
        l503 = l502;
        i504 += i503;
        l504 = l503;
        i505 += i504;
        l505 = l504;
        i506 += i505;
        l506 = l505;
        i507 += i506;
        l507 = l506;
        i508 += i507;
        l508 = l507;
        i509 += i508;
        l509 = l508;
        i510 += i509;
        l510 = l509;
        i511 += i510;
        l511 = l510;
        i512 += i511;
        l512 = l511;
        i513 += i512;
        l513 = l512;
        i514 += i513;
        l514 = l513;
        i515 += i514;
        l515 = l514;
        i516 += i515;
        l516 = l515;
        i517 += i516;
        l517 = l516;
        i518 += i517;
        l518 = l517;
        i519 += i518;
        l519 = l518;
        i520 += i519;
        l520 = l519;
        i521 += i520;
        l521 = l520;
        i522 += i521;
        l522 = l521;
        i523 += i522;
        l523 = l522;
        i524 += i523;
        l524 = l523;
        i525 += i524;
        l525 = l524;
        i526 += i525;
        l526 = l525;
        i527 += i526;
        l527 = l526;
        i528 += i527;
        l528 = l527;
        i529 += i528;
        l529 = l528;
        i530 += i529;
        l530 = l529;
        i531 += i530;
        l531 = l530;
        i532 += i531;
        l532 = l531;
        i533 += i532;
        l533 = l532;
        i534 += i533;
        l534 = l533;
        i535 += i534;
        l535 = l534;
        i536 += i535;
        l536 = l535;
        i537 += i536;
        l537 = l536;
        i538 += i537;
        l538 = l537;
        i539 += i538;
        l539 = l538;
        i540 += i539;
        l540 = l539;
        i541 += i540;
        l541 = l540;
        i542 += i541;
        l542 = l541;
        i543 += i542;
        l543 = l542;
        i544 += i543;
        l544 = l543;
        i545 += i544;
        l545 = l544;
        i546 += i545;
        l546 = l545;
        i547 += i546;
        l547 = l546;
        i548 += i547;
        l548 = l547;
        i549 += i548;
        l549 = l548;
        i550 += i549;
        l550 = l549;
        i551 += i550;
        l551 = l550;
        i552 += i551;
        l552 = l551;
        i553 += i552;
        l553 = l552;
        i554 += i553;
        l554 = l553;
        i555 += i554;
        l555 = l554;
        i556 += i555;
        l556 = l555;
        i557 += i556;
        l557 = l556;
        i558 += i557;
        l558 = l557;
        i559 += i558;
        l559 = l558;
        i560 += i559;
        l560 = l559;
        i561 += i560;
        l561 = l560;
        i562 += i561;
        l562 = l561;
        i563 += i562;
        l563 = l562;
        i564 += i563;
        l564 = l563;
        i565 += i564;
        l565 = l564;
        i566 += i565;
        l566 = l565;
        i567 += i566;
        l567 = l566;
        i568 += i567;
        l568 = l567;
        i569 += i568;
        l569 = l568;
        i570 += i569;
        l570 = l569;
        i571 += i570;
        l571 = l570;
        i572 += i571;
        l572 = l571;
        i573 += i572;
        l573 = l572;
        i574 += i573;
        l574 = l573;
        i575 += i574;
        l575 = l574;
        i576 += i575;
        l576 = l575;
        i577 += i576;
        l577 = l576;
        i578 += i577;
        l578 = l577;
        i579 += i578;
        l579 = l578;
        i580 += i579;
        l580 = l579;
        i581 += i580;
        l581 = l580;
        i582 += i581;
        l582 = l581;
        i583 += i582;
        l583 = l582;
        i584 += i583;
        l584 = l583;
        i585 += i584;
        l585 = l584;
        i586 += i585;
        l586 = l585;
        i587 += i586;
        l587 = l586;
        i588 += i587;
        l588 = l587;
        i589 += i588;
        l589 = l588;
        i590 += i589;
        l590 = l589;
        i591 += i590;
        l591 = l590;
        i592 += i591;
        l592 = l591;
        i593 += i592;
        l593 = l592;
        i594 += i593;
        l594 = l593;
        i595 += i594;
        l595 = l594;
        i596 += i595;
        l596 = l595;
        i597 += i596;
        l597 = l596;
        i598 += i597;
        l598 = l597;
        i599 += i598;
        l599 = l598;
        i600 += i599;
        l600 = l599;
        i601 += i600;
        l601 = l600;
        i602 += i601;
        l602 = l601;
        i603 += i602;
        l603 = l602;
        i604 += i603;
        l604 = l603;
        i605 += i604;
        l605 = l604;
        i606 += i605;
        l606 = l605;
        i607 += i606;
        l607 = l606;
        i608 += i607;
        l608 = l607;
        i609 += i608;
        l609 = l608;
        i610 += i609;
        l610 = l609;
        i611 += i610;
        l611 = l610;
        i612 += i611;
        l612 = l611;
        i613 += i612;
        l613 = l612;
        i614 += i613;
        l614 = l613;
        i615 += i614;
        l615 = l614;
        i616 += i615;
        l616 = l615;
        i617 += i616;
        l617 = l616;
        i618 += i617;
        l618 = l617;
        i619 += i618;
        l619 = l618;
        i620 += i619;
        l620 = l619;
        i621 += i620;
        l621 = l620;
        i622 += i621;
        l622 = l621;
        i623 += i622;
        l623 = l622;
        i624 += i623;
        l624 = l623;
        i625 += i624;
        l625 = l624;
        i626 += i625;
        l626 = l625;
        i627 += i626;
        l627 = l626;
        i628 += i627;
        l628 = l627;
        i629 += i628;
        l629 = l628;
        i630 += i629;
        l630 = l629;
        i631 += i630;
        l631 = l630;
        i632 += i631;
        l632 = l631;
        i633 += i632;
        l633 = l632;
        i634 += i633;
        l634 = l633;
        i635 += i634;
        l635 = l634;
        i636 += i635;
        l636 = l635;
        i637 += i636;
        l637 = l636;
        i638 += i637;
        l638 = l637;
        i639 += i638;
        l639 = l638;
        i640 += i639;
        l640 = l639;
        i641 += i640;
        l641 = l640;
        i642 += i641;
        l642 = l641;
        i643 += i642;
        l643 = l642;
        i644 += i643;
        l644 = l643;
        i645 += i644;
        l645 = l644;
        i646 += i645;
        l646 = l645;
        i647 += i646;
        l647 = l646;
        i648 += i647;
        l648 = l647;
        i649 += i648;
        l649 = l648;
        i650 += i649;
        l650 = l649;
        i651 += i650;
        l651 = l650;
        i652 += i651;
        l652 = l651;
        i653 += i652;
        l653 = l652;
        i654 += i653;
        l654 = l653;
        i655 += i654;
        l655 = l654;
        i656 += i655;
        l656 = l655;
        i657 += i656;
        l657 = l656;
        i658 += i657;
        l658 = l657;
        i659 += i658;
        l659 = l658;
        i660 += i659;
        l660 = l659;
        i661 += i660;
        l661 = l660;
        i662 += i661;
        l662 = l661;
        i663 += i662;
        l663 = l662;
        i664 += i663;
        l664 = l663;
        i665 += i664;
        l665 = l664;
        i666 += i665;
        l666 = l665;
        i667 += i666;
        l667 = l666;
        i668 += i667;
        l668 = l667;
        i669 += i668;
        l669 = l668;
        i670 += i669;
        l670 = l669;
        i671 += i670;
        l671 = l670;
        i672 += i671;
        l672 = l671;
        i673 += i672;
        l673 = l672;
        i674 += i673;
        l674 = l673;
        i675 += i674;
        l675 = l674;
        i676 += i675;
        l676 = l675;
        i677 += i676;
        l677 = l676;
        i678 += i677;
        l678 = l677;
        i679 += i678;
        l679 = l678;
        i680 += i679;
        l680 = l679;
        i681 += i680;
        l681 = l680;
        i682 += i681;
        l682 = l681;
        i683 += i682;
        l683 = l682;
        i684 += i683;
        l684 = l683;
        i685 += i684;
        l685 = l684;
        i686 += i685;
        l686 = l685;
        i687 += i686;
        l687 = l686;
        i688 += i687;
        l688 = l687;
        i689 += i688;
        l689 = l688;
        i690 += i689;
        l690 = l689;
        i691 += i690;
        l691 = l690;
        i692 += i691;
        l692 = l691;
        i693 += i692;
        l693 = l692;
        i694 += i693;
        l694 = l693;
        i695 += i694;
        l695 = l694;
        i696 += i695;
        l696 = l695;
        i697 += i696;
        l697 = l696;
        i698 += i697;
        l698 = l697;
        i699 += i698;
        l699 = l698;
        i700 += i699;
        l700 = l699;
        i701 += i700;
        l701 = l700;
        i702 += i701;
        l702 = l701;
        i703 += i702;
        l703 = l702;
        i704 += i703;
        l704 = l703;
        i705 += i704;
        l705 = l704;
        i706 += i705;
        l706 = l705;
        i707 += i706;
        l707 = l706;
        i708 += i707;
        l708 = l707;
        i709 += i708;
        l709 = l708;
        i710 += i709;
        l710 = l709;
        i711 += i710;
        l711 = l710;
        i712 += i711;
        l712 = l711;
        i713 += i712;
        l713 = l712;
        i714 += i713;
        l714 = l713;
        i715 += i714;
        l715 = l714;
        i716 += i715;
        l716 = l715;
        i717 += i716;
        l717 = l716;
        i718 += i717;
        l718 = l717;
        i719 += i718;
        l719 = l718;
        i720 += i719;
        l720 = l719;
        i721 += i720;
        l721 = l720;
        i722 += i721;
        l722 = l721;
        i723 += i722;
        l723 = l722;
        i724 += i723;
        l724 = l723;
        i725 += i724;
        l725 = l724;
        i726 += i725;
        l726 = l725;
        i727 += i726;
        l727 = l726;
        i728 += i727;
        l728 = l727;
        i729 += i728;
        l729 = l728;
        i730 += i729;
        l730 = l729;
        i731 += i730;
        l731 = l730;
        i732 += i731;
        l732 = l731;
        i733 += i732;
        l733 = l732;
        i734 += i733;
        l734 = l733;
        i735 += i734;
        l735 = l734;
        i736 += i735;
        l736 = l735;
        i737 += i736;
        l737 = l736;
        i738 += i737;
        l738 = l737;
        i739 += i738;
        l739 = l738;
        i740 += i739;
        l740 = l739;
        i741 += i740;
        l741 = l740;
        i742 += i741;
        l742 = l741;
        i743 += i742;
        l743 = l742;
        i744 += i743;
        l744 = l743;
        i745 += i744;
        l745 = l744;
        i746 += i745;
        l746 = l745;
        i747 += i746;
        l747 = l746;
        i748 += i747;
        l748 = l747;
        i749 += i748;
        l749 = l748;
        i750 += i749;
        l750 = l749;
        i751 += i750;
        l751 = l750;
        i752 += i751;
        l752 = l751;
        i753 += i752;
        l753 = l752;
        i754 += i753;
        l754 = l753;
        i755 += i754;
        l755 = l754;
        i756 += i755;
        l756 = l755;
        i757 += i756;
        l757 = l756;
        i758 += i757;
        l758 = l757;
        i759 += i758;
        l759 = l758;
        i760 += i759;
        l760 = l759;
        i761 += i760;
        l761 = l760;
        i762 += i761;
        l762 = l761;
        i763 += i762;
        l763 = l762;
        i764 += i763;
        l764 = l763;
        i765 += i764;
        l765 = l764;
        i766 += i765;
        l766 = l765;
        i767 += i766;
        l767 = l766;
        i768 += i767;
        l768 = l767;
        i769 += i768;
        l769 = l768;
        i770 += i769;
        l770 = l769;
        i771 += i770;
        l771 = l770;
        i772 += i771;
        l772 = l771;
        i773 += i772;
        l773 = l772;
        i774 += i773;
        l774 = l773;
        i775 += i774;
        l775 = l774;
        i776 += i775;
        l776 = l775;
        i777 += i776;
        l777 = l776;
        i778 += i777;
        l778 = l777;
        i779 += i778;
        l779 = l778;
        i780 += i779;
        l780 = l779;
        i781 += i780;
        l781 = l780;
        i782 += i781;
        l782 = l781;
        i783 += i782;
        l783 = l782;
        i784 += i783;
        l784 = l783;
        i785 += i784;
        l785 = l784;
        i786 += i785;
        l786 = l785;
        i787 += i786;
        l787 = l786;
        i788 += i787;
        l788 = l787;
        i789 += i788;
        l789 = l788;
        i790 += i789;
        l790 = l789;
        i791 += i790;
        l791 = l790;
        i792 += i791;
        l792 = l791;
        i793 += i792;
        l793 = l792;
        i794 += i793;
        l794 = l793;
        i795 += i794;
        l795 = l794;
        i796 += i795;
        l796 = l795;
        i797 += i796;
        l797 = l796;
        i798 += i797;
        l798 = l797;
        i799 += i798;
        l799 = l798;
        i800 += i799;
        l800 = l799;
        i801 += i800;
        l801 = l800;
        i802 += i801;
        l802 = l801;
        i803 += i802;
        l803 = l802;
        i804 += i803;
        l804 = l803;
        i805 += i804;
        l805 = l804;
        i806 += i805;
        l806 = l805;
        i807 += i806;
        l807 = l806;
        i808 += i807;
        l808 = l807;
        i809 += i808;
        l809 = l808;
        i810 += i809;
        l810 = l809;
        i811 += i810;
        l811 = l810;
        i812 += i811;
        l812 = l811;
        i813 += i812;
        l813 = l812;
        i814 += i813;
        l814 = l813;
        i815 += i814;
        l815 = l814;
        i816 += i815;
        l816 = l815;
        i817 += i816;
        l817 = l816;
        i818 += i817;
        l818 = l817;
        i819 += i818;
        l819 = l818;
        i820 += i819;
        l820 = l819;
        i821 += i820;
        l821 = l820;
        i822 += i821;
        l822 = l821;
        i823 += i822;
        l823 = l822;
        i824 += i823;
        l824 = l823;
        i825 += i824;
        l825 = l824;
        i826 += i825;
        l826 = l825;
        i827 += i826;
        l827 = l826;
        i828 += i827;
        l828 = l827;
        i829 += i828;
        l829 = l828;
        i830 += i829;
        l830 = l829;
        i831 += i830;
        l831 = l830;
        i832 += i831;
        l832 = l831;
        i833 += i832;
        l833 = l832;
        i834 += i833;
        l834 = l833;
        i835 += i834;
        l835 = l834;
        i836 += i835;
        l836 = l835;
        i837 += i836;
        l837 = l836;
        i838 += i837;
        l838 = l837;
        i839 += i838;
        l839 = l838;
        i840 += i839;
        l840 = l839;
        i841 += i840;
        l841 = l840;
        i842 += i841;
        l842 = l841;
        i843 += i842;
        l843 = l842;
        i844 += i843;
        l844 = l843;
        i845 += i844;
        l845 = l844;
        i846 += i845;
        l846 = l845;
        i847 += i846;
        l847 = l846;
        i848 += i847;
        l848 = l847;
        i849 += i848;
        l849 = l848;
        i850 += i849;
        l850 = l849;
        i851 += i850;
        l851 = l850;
        i852 += i851;
        l852 = l851;
        i853 += i852;
        l853 = l852;
        i854 += i853;
        l854 = l853;
        i855 += i854;
        l855 = l854;
        i856 += i855;
        l856 = l855;
        i857 += i856;
        l857 = l856;
        i858 += i857;
        l858 = l857;
        i859 += i858;
        l859 = l858;
        i860 += i859;
        l860 = l859;
        i861 += i860;
        l861 = l860;
        i862 += i861;
        l862 = l861;
        i863 += i862;
        l863 = l862;
        i864 += i863;
        l864 = l863;
        i865 += i864;
        l865 = l864;
        i866 += i865;
        l866 = l865;
        i867 += i866;
        l867 = l866;
        i868 += i867;
        l868 = l867;
        i869 += i868;
        l869 = l868;
        i870 += i869;
        l870 = l869;
        i871 += i870;
        l871 = l870;
        i872 += i871;
        l872 = l871;
        i873 += i872;
        l873 = l872;
        i874 += i873;
        l874 = l873;
        i875 += i874;
        l875 = l874;
        i876 += i875;
        l876 = l875;
        i877 += i876;
        l877 = l876;
        i878 += i877;
        l878 = l877;
        i879 += i878;
        l879 = l878;
        i880 += i879;
        l880 = l879;
        i881 += i880;
        l881 = l880;
        i882 += i881;
        l882 = l881;
        i883 += i882;
        l883 = l882;
        i884 += i883;
        l884 = l883;
        i885 += i884;
        l885 = l884;
        i886 += i885;
        l886 = l885;
        i887 += i886;
        l887 = l886;
        i888 += i887;
        l888 = l887;
        i889 += i888;
        l889 = l888;
        i890 += i889;
        l890 = l889;
        i891 += i890;
        l891 = l890;
        i892 += i891;
        l892 = l891;
        i893 += i892;
        l893 = l892;
        i894 += i893;
        l894 = l893;
        i895 += i894;
        l895 = l894;
        i896 += i895;
        l896 = l895;
        i897 += i896;
        l897 = l896;
        i898 += i897;
        l898 = l897;
        i899 += i898;
        l899 = l898;
        i900 += i899;
        l900 = l899;
        i901 += i900;
        l901 = l900;
        i902 += i901;
        l902 = l901;
        i903 += i902;
        l903 = l902;
        i904 += i903;
        l904 = l903;
        i905 += i904;
        l905 = l904;
        i906 += i905;
        l906 = l905;
        i907 += i906;
        l907 = l906;
        i908 += i907;
        l908 = l907;
        i909 += i908;
        l909 = l908;
        i910 += i909;
        l910 = l909;
        i911 += i910;
        l911 = l910;
        i912 += i911;
        l912 = l911;
        i913 += i912;
        l913 = l912;
        i914 += i913;
        l914 = l913;
        i915 += i914;
        l915 = l914;
        i916 += i915;
        l916 = l915;
        i917 += i916;
        l917 = l916;
        i918 += i917;
        l918 = l917;
        i919 += i918;
        l919 = l918;
        i920 += i919;
        l920 = l919;
        i921 += i920;
        l921 = l920;
        i922 += i921;
        l922 = l921;
        i923 += i922;
        l923 = l922;
        i924 += i923;
        l924 = l923;
        i925 += i924;
        l925 = l924;
        i926 += i925;
        l926 = l925;
        i927 += i926;
        l927 = l926;
        i928 += i927;
        l928 = l927;
        i929 += i928;
        l929 = l928;
        i930 += i929;
        l930 = l929;
        i931 += i930;
        l931 = l930;
        i932 += i931;
        l932 = l931;
        i933 += i932;
        l933 = l932;
        i934 += i933;
        l934 = l933;
        i935 += i934;
        l935 = l934;
        i936 += i935;
        l936 = l935;
        i937 += i936;
        l937 = l936;
        i938 += i937;
        l938 = l937;
        i939 += i938;
        l939 = l938;
        i940 += i939;
        l940 = l939;
        i941 += i940;
        l941 = l940;
        i942 += i941;
        l942 = l941;
        i943 += i942;
        l943 = l942;
        i944 += i943;
        l944 = l943;
        i945 += i944;
        l945 = l944;
        i946 += i945;
        l946 = l945;
        i947 += i946;
        l947 = l946;
        i948 += i947;
        l948 = l947;
        i949 += i948;
        l949 = l948;
        i950 += i949;
        l950 = l949;
        i951 += i950;
        l951 = l950;
        i952 += i951;
        l952 = l951;
        i953 += i952;
        l953 = l952;
        i954 += i953;
        l954 = l953;
        i955 += i954;
        l955 = l954;
        i956 += i955;
        l956 = l955;
        i957 += i956;
        l957 = l956;
        i958 += i957;
        l958 = l957;
        i959 += i958;
        l959 = l958;
        i960 += i959;
        l960 = l959;
        i961 += i960;
        l961 = l960;
        i962 += i961;
        l962 = l961;
        i963 += i962;
        l963 = l962;
        i964 += i963;
        l964 = l963;
        i965 += i964;
        l965 = l964;
        i966 += i965;
        l966 = l965;
        i967 += i966;
        l967 = l966;
        i968 += i967;
        l968 = l967;
        i969 += i968;
        l969 = l968;
        i970 += i969;
        l970 = l969;
        i971 += i970;
        l971 = l970;
        i972 += i971;
        l972 = l971;
        i973 += i972;
        l973 = l972;
        i974 += i973;
        l974 = l973;
        i975 += i974;
        l975 = l974;
        i976 += i975;
        l976 = l975;
        i977 += i976;
        l977 = l976;
        i978 += i977;
        l978 = l977;
        i979 += i978;
        l979 = l978;
        i980 += i979;
        l980 = l979;
        i981 += i980;
        l981 = l980;
        i982 += i981;
        l982 = l981;
        i983 += i982;
        l983 = l982;
        i984 += i983;
        l984 = l983;
        i985 += i984;
        l985 = l984;
        i986 += i985;
        l986 = l985;
        i987 += i986;
        l987 = l986;
        i988 += i987;
        l988 = l987;
        i989 += i988;
        l989 = l988;
        i990 += i989;
        l990 = l989;
        i991 += i990;
        l991 = l990;
        i992 += i991;
        l992 = l991;
        i993 += i992;
        l993 = l992;
        i994 += i993;
        l994 = l993;
        i995 += i994;
        l995 = l994;
        i996 += i995;
        l996 = l995;
        i997 += i996;
        l997 = l996;
        i998 += i997;
        l998 = l997;
        i999 += i998;
        l999 = l998;
        return i999 + l999;
    }

    static double largeFrameFloat() {
        float f0 = 0;
        double d0 = 0;
        float f1 = 1;
        double d1 = 1;
        float f2 = 2;
        double d2 = 2;
        float f3 = 3;
        double d3 = 3;
        float f4 = 4;
        double d4 = 4;
        float f5 = 5;
        double d5 = 5;
        float f6 = 6;
        double d6 = 6;
        float f7 = 7;
        double d7 = 7;
        float f8 = 8;
        double d8 = 8;
        float f9 = 9;
        double d9 = 9;
        float f10 = 10;
        double d10 = 10;
        float f11 = 11;
        double d11 = 11;
        float f12 = 12;
        double d12 = 12;
        float f13 = 13;
        double d13 = 13;
        float f14 = 14;
        double d14 = 14;
        float f15 = 15;
        double d15 = 15;
        float f16 = 16;
        double d16 = 16;
        float f17 = 17;
        double d17 = 17;
        float f18 = 18;
        double d18 = 18;
        float f19 = 19;
        double d19 = 19;
        float f20 = 20;
        double d20 = 20;
        float f21 = 21;
        double d21 = 21;
        float f22 = 22;
        double d22 = 22;
        float f23 = 23;
        double d23 = 23;
        float f24 = 24;
        double d24 = 24;
        float f25 = 25;
        double d25 = 25;
        float f26 = 26;
        double d26 = 26;
        float f27 = 27;
        double d27 = 27;
        float f28 = 28;
        double d28 = 28;
        float f29 = 29;
        double d29 = 29;
        float f30 = 30;
        double d30 = 30;
        float f31 = 31;
        double d31 = 31;
        float f32 = 32;
        double d32 = 32;
        float f33 = 33;
        double d33 = 33;
        float f34 = 34;
        double d34 = 34;
        float f35 = 35;
        double d35 = 35;
        float f36 = 36;
        double d36 = 36;
        float f37 = 37;
        double d37 = 37;
        float f38 = 38;
        double d38 = 38;
        float f39 = 39;
        double d39 = 39;
        float f40 = 40;
        double d40 = 40;
        float f41 = 41;
        double d41 = 41;
        float f42 = 42;
        double d42 = 42;
        float f43 = 43;
        double d43 = 43;
        float f44 = 44;
        double d44 = 44;
        float f45 = 45;
        double d45 = 45;
        float f46 = 46;
        double d46 = 46;
        float f47 = 47;
        double d47 = 47;
        float f48 = 48;
        double d48 = 48;
        float f49 = 49;
        double d49 = 49;
        float f50 = 50;
        double d50 = 50;
        float f51 = 51;
        double d51 = 51;
        float f52 = 52;
        double d52 = 52;
        float f53 = 53;
        double d53 = 53;
        float f54 = 54;
        double d54 = 54;
        float f55 = 55;
        double d55 = 55;
        float f56 = 56;
        double d56 = 56;
        float f57 = 57;
        double d57 = 57;
        float f58 = 58;
        double d58 = 58;
        float f59 = 59;
        double d59 = 59;
        float f60 = 60;
        double d60 = 60;
        float f61 = 61;
        double d61 = 61;
        float f62 = 62;
        double d62 = 62;
        float f63 = 63;
        double d63 = 63;
        float f64 = 64;
        double d64 = 64;
        float f65 = 65;
        double d65 = 65;
        float f66 = 66;
        double d66 = 66;
        float f67 = 67;
        double d67 = 67;
        float f68 = 68;
        double d68 = 68;
        float f69 = 69;
        double d69 = 69;
        float f70 = 70;
        double d70 = 70;
        float f71 = 71;
        double d71 = 71;
        float f72 = 72;
        double d72 = 72;
        float f73 = 73;
        double d73 = 73;
        float f74 = 74;
        double d74 = 74;
        float f75 = 75;
        double d75 = 75;
        float f76 = 76;
        double d76 = 76;
        float f77 = 77;
        double d77 = 77;
        float f78 = 78;
        double d78 = 78;
        float f79 = 79;
        double d79 = 79;
        float f80 = 80;
        double d80 = 80;
        float f81 = 81;
        double d81 = 81;
        float f82 = 82;
        double d82 = 82;
        float f83 = 83;
        double d83 = 83;
        float f84 = 84;
        double d84 = 84;
        float f85 = 85;
        double d85 = 85;
        float f86 = 86;
        double d86 = 86;
        float f87 = 87;
        double d87 = 87;
        float f88 = 88;
        double d88 = 88;
        float f89 = 89;
        double d89 = 89;
        float f90 = 90;
        double d90 = 90;
        float f91 = 91;
        double d91 = 91;
        float f92 = 92;
        double d92 = 92;
        float f93 = 93;
        double d93 = 93;
        float f94 = 94;
        double d94 = 94;
        float f95 = 95;
        double d95 = 95;
        float f96 = 96;
        double d96 = 96;
        float f97 = 97;
        double d97 = 97;
        float f98 = 98;
        double d98 = 98;
        float f99 = 99;
        double d99 = 99;
        float f100 = 100;
        double d100 = 100;
        float f101 = 101;
        double d101 = 101;
        float f102 = 102;
        double d102 = 102;
        float f103 = 103;
        double d103 = 103;
        float f104 = 104;
        double d104 = 104;
        float f105 = 105;
        double d105 = 105;
        float f106 = 106;
        double d106 = 106;
        float f107 = 107;
        double d107 = 107;
        float f108 = 108;
        double d108 = 108;
        float f109 = 109;
        double d109 = 109;
        float f110 = 110;
        double d110 = 110;
        float f111 = 111;
        double d111 = 111;
        float f112 = 112;
        double d112 = 112;
        float f113 = 113;
        double d113 = 113;
        float f114 = 114;
        double d114 = 114;
        float f115 = 115;
        double d115 = 115;
        float f116 = 116;
        double d116 = 116;
        float f117 = 117;
        double d117 = 117;
        float f118 = 118;
        double d118 = 118;
        float f119 = 119;
        double d119 = 119;
        float f120 = 120;
        double d120 = 120;
        float f121 = 121;
        double d121 = 121;
        float f122 = 122;
        double d122 = 122;
        float f123 = 123;
        double d123 = 123;
        float f124 = 124;
        double d124 = 124;
        float f125 = 125;
        double d125 = 125;
        float f126 = 126;
        double d126 = 126;
        float f127 = 127;
        double d127 = 127;
        float f128 = 128;
        double d128 = 128;
        float f129 = 129;
        double d129 = 129;
        float f130 = 130;
        double d130 = 130;
        float f131 = 131;
        double d131 = 131;
        float f132 = 132;
        double d132 = 132;
        float f133 = 133;
        double d133 = 133;
        float f134 = 134;
        double d134 = 134;
        float f135 = 135;
        double d135 = 135;
        float f136 = 136;
        double d136 = 136;
        float f137 = 137;
        double d137 = 137;
        float f138 = 138;
        double d138 = 138;
        float f139 = 139;
        double d139 = 139;
        float f140 = 140;
        double d140 = 140;
        float f141 = 141;
        double d141 = 141;
        float f142 = 142;
        double d142 = 142;
        float f143 = 143;
        double d143 = 143;
        float f144 = 144;
        double d144 = 144;
        float f145 = 145;
        double d145 = 145;
        float f146 = 146;
        double d146 = 146;
        float f147 = 147;
        double d147 = 147;
        float f148 = 148;
        double d148 = 148;
        float f149 = 149;
        double d149 = 149;
        float f150 = 150;
        double d150 = 150;
        float f151 = 151;
        double d151 = 151;
        float f152 = 152;
        double d152 = 152;
        float f153 = 153;
        double d153 = 153;
        float f154 = 154;
        double d154 = 154;
        float f155 = 155;
        double d155 = 155;
        float f156 = 156;
        double d156 = 156;
        float f157 = 157;
        double d157 = 157;
        float f158 = 158;
        double d158 = 158;
        float f159 = 159;
        double d159 = 159;
        float f160 = 160;
        double d160 = 160;
        float f161 = 161;
        double d161 = 161;
        float f162 = 162;
        double d162 = 162;
        float f163 = 163;
        double d163 = 163;
        float f164 = 164;
        double d164 = 164;
        float f165 = 165;
        double d165 = 165;
        float f166 = 166;
        double d166 = 166;
        float f167 = 167;
        double d167 = 167;
        float f168 = 168;
        double d168 = 168;
        float f169 = 169;
        double d169 = 169;
        float f170 = 170;
        double d170 = 170;
        float f171 = 171;
        double d171 = 171;
        float f172 = 172;
        double d172 = 172;
        float f173 = 173;
        double d173 = 173;
        float f174 = 174;
        double d174 = 174;
        float f175 = 175;
        double d175 = 175;
        float f176 = 176;
        double d176 = 176;
        float f177 = 177;
        double d177 = 177;
        float f178 = 178;
        double d178 = 178;
        float f179 = 179;
        double d179 = 179;
        float f180 = 180;
        double d180 = 180;
        float f181 = 181;
        double d181 = 181;
        float f182 = 182;
        double d182 = 182;
        float f183 = 183;
        double d183 = 183;
        float f184 = 184;
        double d184 = 184;
        float f185 = 185;
        double d185 = 185;
        float f186 = 186;
        double d186 = 186;
        float f187 = 187;
        double d187 = 187;
        float f188 = 188;
        double d188 = 188;
        float f189 = 189;
        double d189 = 189;
        float f190 = 190;
        double d190 = 190;
        float f191 = 191;
        double d191 = 191;
        float f192 = 192;
        double d192 = 192;
        float f193 = 193;
        double d193 = 193;
        float f194 = 194;
        double d194 = 194;
        float f195 = 195;
        double d195 = 195;
        float f196 = 196;
        double d196 = 196;
        float f197 = 197;
        double d197 = 197;
        float f198 = 198;
        double d198 = 198;
        float f199 = 199;
        double d199 = 199;
        float f200 = 200;
        double d200 = 200;
        float f201 = 201;
        double d201 = 201;
        float f202 = 202;
        double d202 = 202;
        float f203 = 203;
        double d203 = 203;
        float f204 = 204;
        double d204 = 204;
        float f205 = 205;
        double d205 = 205;
        float f206 = 206;
        double d206 = 206;
        float f207 = 207;
        double d207 = 207;
        float f208 = 208;
        double d208 = 208;
        float f209 = 209;
        double d209 = 209;
        float f210 = 210;
        double d210 = 210;
        float f211 = 211;
        double d211 = 211;
        float f212 = 212;
        double d212 = 212;
        float f213 = 213;
        double d213 = 213;
        float f214 = 214;
        double d214 = 214;
        float f215 = 215;
        double d215 = 215;
        float f216 = 216;
        double d216 = 216;
        float f217 = 217;
        double d217 = 217;
        float f218 = 218;
        double d218 = 218;
        float f219 = 219;
        double d219 = 219;
        float f220 = 220;
        double d220 = 220;
        float f221 = 221;
        double d221 = 221;
        float f222 = 222;
        double d222 = 222;
        float f223 = 223;
        double d223 = 223;
        float f224 = 224;
        double d224 = 224;
        float f225 = 225;
        double d225 = 225;
        float f226 = 226;
        double d226 = 226;
        float f227 = 227;
        double d227 = 227;
        float f228 = 228;
        double d228 = 228;
        float f229 = 229;
        double d229 = 229;
        float f230 = 230;
        double d230 = 230;
        float f231 = 231;
        double d231 = 231;
        float f232 = 232;
        double d232 = 232;
        float f233 = 233;
        double d233 = 233;
        float f234 = 234;
        double d234 = 234;
        float f235 = 235;
        double d235 = 235;
        float f236 = 236;
        double d236 = 236;
        float f237 = 237;
        double d237 = 237;
        float f238 = 238;
        double d238 = 238;
        float f239 = 239;
        double d239 = 239;
        float f240 = 240;
        double d240 = 240;
        float f241 = 241;
        double d241 = 241;
        float f242 = 242;
        double d242 = 242;
        float f243 = 243;
        double d243 = 243;
        float f244 = 244;
        double d244 = 244;
        float f245 = 245;
        double d245 = 245;
        float f246 = 246;
        double d246 = 246;
        float f247 = 247;
        double d247 = 247;
        float f248 = 248;
        double d248 = 248;
        float f249 = 249;
        double d249 = 249;
        float f250 = 250;
        double d250 = 250;
        float f251 = 251;
        double d251 = 251;
        float f252 = 252;
        double d252 = 252;
        float f253 = 253;
        double d253 = 253;
        float f254 = 254;
        double d254 = 254;
        float f255 = 255;
        double d255 = 255;
        float f256 = 256;
        double d256 = 256;
        float f257 = 257;
        double d257 = 257;
        float f258 = 258;
        double d258 = 258;
        float f259 = 259;
        double d259 = 259;
        float f260 = 260;
        double d260 = 260;
        float f261 = 261;
        double d261 = 261;
        float f262 = 262;
        double d262 = 262;
        float f263 = 263;
        double d263 = 263;
        float f264 = 264;
        double d264 = 264;
        float f265 = 265;
        double d265 = 265;
        float f266 = 266;
        double d266 = 266;
        float f267 = 267;
        double d267 = 267;
        float f268 = 268;
        double d268 = 268;
        float f269 = 269;
        double d269 = 269;
        float f270 = 270;
        double d270 = 270;
        float f271 = 271;
        double d271 = 271;
        float f272 = 272;
        double d272 = 272;
        float f273 = 273;
        double d273 = 273;
        float f274 = 274;
        double d274 = 274;
        float f275 = 275;
        double d275 = 275;
        float f276 = 276;
        double d276 = 276;
        float f277 = 277;
        double d277 = 277;
        float f278 = 278;
        double d278 = 278;
        float f279 = 279;
        double d279 = 279;
        float f280 = 280;
        double d280 = 280;
        float f281 = 281;
        double d281 = 281;
        float f282 = 282;
        double d282 = 282;
        float f283 = 283;
        double d283 = 283;
        float f284 = 284;
        double d284 = 284;
        float f285 = 285;
        double d285 = 285;
        float f286 = 286;
        double d286 = 286;
        float f287 = 287;
        double d287 = 287;
        float f288 = 288;
        double d288 = 288;
        float f289 = 289;
        double d289 = 289;
        float f290 = 290;
        double d290 = 290;
        float f291 = 291;
        double d291 = 291;
        float f292 = 292;
        double d292 = 292;
        float f293 = 293;
        double d293 = 293;
        float f294 = 294;
        double d294 = 294;
        float f295 = 295;
        double d295 = 295;
        float f296 = 296;
        double d296 = 296;
        float f297 = 297;
        double d297 = 297;
        float f298 = 298;
        double d298 = 298;
        float f299 = 299;
        double d299 = 299;
        float f300 = 300;
        double d300 = 300;
        float f301 = 301;
        double d301 = 301;
        float f302 = 302;
        double d302 = 302;
        float f303 = 303;
        double d303 = 303;
        float f304 = 304;
        double d304 = 304;
        float f305 = 305;
        double d305 = 305;
        float f306 = 306;
        double d306 = 306;
        float f307 = 307;
        double d307 = 307;
        float f308 = 308;
        double d308 = 308;
        float f309 = 309;
        double d309 = 309;
        float f310 = 310;
        double d310 = 310;
        float f311 = 311;
        double d311 = 311;
        float f312 = 312;
        double d312 = 312;
        float f313 = 313;
        double d313 = 313;
        float f314 = 314;
        double d314 = 314;
        float f315 = 315;
        double d315 = 315;
        float f316 = 316;
        double d316 = 316;
        float f317 = 317;
        double d317 = 317;
        float f318 = 318;
        double d318 = 318;
        float f319 = 319;
        double d319 = 319;
        float f320 = 320;
        double d320 = 320;
        float f321 = 321;
        double d321 = 321;
        float f322 = 322;
        double d322 = 322;
        float f323 = 323;
        double d323 = 323;
        float f324 = 324;
        double d324 = 324;
        float f325 = 325;
        double d325 = 325;
        float f326 = 326;
        double d326 = 326;
        float f327 = 327;
        double d327 = 327;
        float f328 = 328;
        double d328 = 328;
        float f329 = 329;
        double d329 = 329;
        float f330 = 330;
        double d330 = 330;
        float f331 = 331;
        double d331 = 331;
        float f332 = 332;
        double d332 = 332;
        float f333 = 333;
        double d333 = 333;
        float f334 = 334;
        double d334 = 334;
        float f335 = 335;
        double d335 = 335;
        float f336 = 336;
        double d336 = 336;
        float f337 = 337;
        double d337 = 337;
        float f338 = 338;
        double d338 = 338;
        float f339 = 339;
        double d339 = 339;
        float f340 = 340;
        double d340 = 340;
        float f341 = 341;
        double d341 = 341;
        float f342 = 342;
        double d342 = 342;
        float f343 = 343;
        double d343 = 343;
        float f344 = 344;
        double d344 = 344;
        float f345 = 345;
        double d345 = 345;
        float f346 = 346;
        double d346 = 346;
        float f347 = 347;
        double d347 = 347;
        float f348 = 348;
        double d348 = 348;
        float f349 = 349;
        double d349 = 349;
        float f350 = 350;
        double d350 = 350;
        float f351 = 351;
        double d351 = 351;
        float f352 = 352;
        double d352 = 352;
        float f353 = 353;
        double d353 = 353;
        float f354 = 354;
        double d354 = 354;
        float f355 = 355;
        double d355 = 355;
        float f356 = 356;
        double d356 = 356;
        float f357 = 357;
        double d357 = 357;
        float f358 = 358;
        double d358 = 358;
        float f359 = 359;
        double d359 = 359;
        float f360 = 360;
        double d360 = 360;
        float f361 = 361;
        double d361 = 361;
        float f362 = 362;
        double d362 = 362;
        float f363 = 363;
        double d363 = 363;
        float f364 = 364;
        double d364 = 364;
        float f365 = 365;
        double d365 = 365;
        float f366 = 366;
        double d366 = 366;
        float f367 = 367;
        double d367 = 367;
        float f368 = 368;
        double d368 = 368;
        float f369 = 369;
        double d369 = 369;
        float f370 = 370;
        double d370 = 370;
        float f371 = 371;
        double d371 = 371;
        float f372 = 372;
        double d372 = 372;
        float f373 = 373;
        double d373 = 373;
        float f374 = 374;
        double d374 = 374;
        float f375 = 375;
        double d375 = 375;
        float f376 = 376;
        double d376 = 376;
        float f377 = 377;
        double d377 = 377;
        float f378 = 378;
        double d378 = 378;
        float f379 = 379;
        double d379 = 379;
        float f380 = 380;
        double d380 = 380;
        float f381 = 381;
        double d381 = 381;
        float f382 = 382;
        double d382 = 382;
        float f383 = 383;
        double d383 = 383;
        float f384 = 384;
        double d384 = 384;
        float f385 = 385;
        double d385 = 385;
        float f386 = 386;
        double d386 = 386;
        float f387 = 387;
        double d387 = 387;
        float f388 = 388;
        double d388 = 388;
        float f389 = 389;
        double d389 = 389;
        float f390 = 390;
        double d390 = 390;
        float f391 = 391;
        double d391 = 391;
        float f392 = 392;
        double d392 = 392;
        float f393 = 393;
        double d393 = 393;
        float f394 = 394;
        double d394 = 394;
        float f395 = 395;
        double d395 = 395;
        float f396 = 396;
        double d396 = 396;
        float f397 = 397;
        double d397 = 397;
        float f398 = 398;
        double d398 = 398;
        float f399 = 399;
        double d399 = 399;
        float f400 = 400;
        double d400 = 400;
        float f401 = 401;
        double d401 = 401;
        float f402 = 402;
        double d402 = 402;
        float f403 = 403;
        double d403 = 403;
        float f404 = 404;
        double d404 = 404;
        float f405 = 405;
        double d405 = 405;
        float f406 = 406;
        double d406 = 406;
        float f407 = 407;
        double d407 = 407;
        float f408 = 408;
        double d408 = 408;
        float f409 = 409;
        double d409 = 409;
        float f410 = 410;
        double d410 = 410;
        float f411 = 411;
        double d411 = 411;
        float f412 = 412;
        double d412 = 412;
        float f413 = 413;
        double d413 = 413;
        float f414 = 414;
        double d414 = 414;
        float f415 = 415;
        double d415 = 415;
        float f416 = 416;
        double d416 = 416;
        float f417 = 417;
        double d417 = 417;
        float f418 = 418;
        double d418 = 418;
        float f419 = 419;
        double d419 = 419;
        float f420 = 420;
        double d420 = 420;
        float f421 = 421;
        double d421 = 421;
        float f422 = 422;
        double d422 = 422;
        float f423 = 423;
        double d423 = 423;
        float f424 = 424;
        double d424 = 424;
        float f425 = 425;
        double d425 = 425;
        float f426 = 426;
        double d426 = 426;
        float f427 = 427;
        double d427 = 427;
        float f428 = 428;
        double d428 = 428;
        float f429 = 429;
        double d429 = 429;
        float f430 = 430;
        double d430 = 430;
        float f431 = 431;
        double d431 = 431;
        float f432 = 432;
        double d432 = 432;
        float f433 = 433;
        double d433 = 433;
        float f434 = 434;
        double d434 = 434;
        float f435 = 435;
        double d435 = 435;
        float f436 = 436;
        double d436 = 436;
        float f437 = 437;
        double d437 = 437;
        float f438 = 438;
        double d438 = 438;
        float f439 = 439;
        double d439 = 439;
        float f440 = 440;
        double d440 = 440;
        float f441 = 441;
        double d441 = 441;
        float f442 = 442;
        double d442 = 442;
        float f443 = 443;
        double d443 = 443;
        float f444 = 444;
        double d444 = 444;
        float f445 = 445;
        double d445 = 445;
        float f446 = 446;
        double d446 = 446;
        float f447 = 447;
        double d447 = 447;
        float f448 = 448;
        double d448 = 448;
        float f449 = 449;
        double d449 = 449;
        float f450 = 450;
        double d450 = 450;
        float f451 = 451;
        double d451 = 451;
        float f452 = 452;
        double d452 = 452;
        float f453 = 453;
        double d453 = 453;
        float f454 = 454;
        double d454 = 454;
        float f455 = 455;
        double d455 = 455;
        float f456 = 456;
        double d456 = 456;
        float f457 = 457;
        double d457 = 457;
        float f458 = 458;
        double d458 = 458;
        float f459 = 459;
        double d459 = 459;
        float f460 = 460;
        double d460 = 460;
        float f461 = 461;
        double d461 = 461;
        float f462 = 462;
        double d462 = 462;
        float f463 = 463;
        double d463 = 463;
        float f464 = 464;
        double d464 = 464;
        float f465 = 465;
        double d465 = 465;
        float f466 = 466;
        double d466 = 466;
        float f467 = 467;
        double d467 = 467;
        float f468 = 468;
        double d468 = 468;
        float f469 = 469;
        double d469 = 469;
        float f470 = 470;
        double d470 = 470;
        float f471 = 471;
        double d471 = 471;
        float f472 = 472;
        double d472 = 472;
        float f473 = 473;
        double d473 = 473;
        float f474 = 474;
        double d474 = 474;
        float f475 = 475;
        double d475 = 475;
        float f476 = 476;
        double d476 = 476;
        float f477 = 477;
        double d477 = 477;
        float f478 = 478;
        double d478 = 478;
        float f479 = 479;
        double d479 = 479;
        float f480 = 480;
        double d480 = 480;
        float f481 = 481;
        double d481 = 481;
        float f482 = 482;
        double d482 = 482;
        float f483 = 483;
        double d483 = 483;
        float f484 = 484;
        double d484 = 484;
        float f485 = 485;
        double d485 = 485;
        float f486 = 486;
        double d486 = 486;
        float f487 = 487;
        double d487 = 487;
        float f488 = 488;
        double d488 = 488;
        float f489 = 489;
        double d489 = 489;
        float f490 = 490;
        double d490 = 490;
        float f491 = 491;
        double d491 = 491;
        float f492 = 492;
        double d492 = 492;
        float f493 = 493;
        double d493 = 493;
        float f494 = 494;
        double d494 = 494;
        float f495 = 495;
        double d495 = 495;
        float f496 = 496;
        double d496 = 496;
        float f497 = 497;
        double d497 = 497;
        float f498 = 498;
        double d498 = 498;
        float f499 = 499;
        double d499 = 499;
        float f500 = 500;
        double d500 = 500;
        float f501 = 501;
        double d501 = 501;
        float f502 = 502;
        double d502 = 502;
        float f503 = 503;
        double d503 = 503;
        float f504 = 504;
        double d504 = 504;
        float f505 = 505;
        double d505 = 505;
        float f506 = 506;
        double d506 = 506;
        float f507 = 507;
        double d507 = 507;
        float f508 = 508;
        double d508 = 508;
        float f509 = 509;
        double d509 = 509;
        float f510 = 510;
        double d510 = 510;
        float f511 = 511;
        double d511 = 511;
        float f512 = 512;
        double d512 = 512;
        float f513 = 513;
        double d513 = 513;
        float f514 = 514;
        double d514 = 514;
        float f515 = 515;
        double d515 = 515;
        float f516 = 516;
        double d516 = 516;
        float f517 = 517;
        double d517 = 517;
        float f518 = 518;
        double d518 = 518;
        float f519 = 519;
        double d519 = 519;
        float f520 = 520;
        double d520 = 520;
        float f521 = 521;
        double d521 = 521;
        float f522 = 522;
        double d522 = 522;
        float f523 = 523;
        double d523 = 523;
        float f524 = 524;
        double d524 = 524;
        float f525 = 525;
        double d525 = 525;
        float f526 = 526;
        double d526 = 526;
        float f527 = 527;
        double d527 = 527;
        float f528 = 528;
        double d528 = 528;
        float f529 = 529;
        double d529 = 529;
        float f530 = 530;
        double d530 = 530;
        float f531 = 531;
        double d531 = 531;
        float f532 = 532;
        double d532 = 532;
        float f533 = 533;
        double d533 = 533;
        float f534 = 534;
        double d534 = 534;
        float f535 = 535;
        double d535 = 535;
        float f536 = 536;
        double d536 = 536;
        float f537 = 537;
        double d537 = 537;
        float f538 = 538;
        double d538 = 538;
        float f539 = 539;
        double d539 = 539;
        float f540 = 540;
        double d540 = 540;
        float f541 = 541;
        double d541 = 541;
        float f542 = 542;
        double d542 = 542;
        float f543 = 543;
        double d543 = 543;
        float f544 = 544;
        double d544 = 544;
        float f545 = 545;
        double d545 = 545;
        float f546 = 546;
        double d546 = 546;
        float f547 = 547;
        double d547 = 547;
        float f548 = 548;
        double d548 = 548;
        float f549 = 549;
        double d549 = 549;
        float f550 = 550;
        double d550 = 550;
        float f551 = 551;
        double d551 = 551;
        float f552 = 552;
        double d552 = 552;
        float f553 = 553;
        double d553 = 553;
        float f554 = 554;
        double d554 = 554;
        float f555 = 555;
        double d555 = 555;
        float f556 = 556;
        double d556 = 556;
        float f557 = 557;
        double d557 = 557;
        float f558 = 558;
        double d558 = 558;
        float f559 = 559;
        double d559 = 559;
        float f560 = 560;
        double d560 = 560;
        float f561 = 561;
        double d561 = 561;
        float f562 = 562;
        double d562 = 562;
        float f563 = 563;
        double d563 = 563;
        float f564 = 564;
        double d564 = 564;
        float f565 = 565;
        double d565 = 565;
        float f566 = 566;
        double d566 = 566;
        float f567 = 567;
        double d567 = 567;
        float f568 = 568;
        double d568 = 568;
        float f569 = 569;
        double d569 = 569;
        float f570 = 570;
        double d570 = 570;
        float f571 = 571;
        double d571 = 571;
        float f572 = 572;
        double d572 = 572;
        float f573 = 573;
        double d573 = 573;
        float f574 = 574;
        double d574 = 574;
        float f575 = 575;
        double d575 = 575;
        float f576 = 576;
        double d576 = 576;
        float f577 = 577;
        double d577 = 577;
        float f578 = 578;
        double d578 = 578;
        float f579 = 579;
        double d579 = 579;
        float f580 = 580;
        double d580 = 580;
        float f581 = 581;
        double d581 = 581;
        float f582 = 582;
        double d582 = 582;
        float f583 = 583;
        double d583 = 583;
        float f584 = 584;
        double d584 = 584;
        float f585 = 585;
        double d585 = 585;
        float f586 = 586;
        double d586 = 586;
        float f587 = 587;
        double d587 = 587;
        float f588 = 588;
        double d588 = 588;
        float f589 = 589;
        double d589 = 589;
        float f590 = 590;
        double d590 = 590;
        float f591 = 591;
        double d591 = 591;
        float f592 = 592;
        double d592 = 592;
        float f593 = 593;
        double d593 = 593;
        float f594 = 594;
        double d594 = 594;
        float f595 = 595;
        double d595 = 595;
        float f596 = 596;
        double d596 = 596;
        float f597 = 597;
        double d597 = 597;
        float f598 = 598;
        double d598 = 598;
        float f599 = 599;
        double d599 = 599;
        float f600 = 600;
        double d600 = 600;
        float f601 = 601;
        double d601 = 601;
        float f602 = 602;
        double d602 = 602;
        float f603 = 603;
        double d603 = 603;
        float f604 = 604;
        double d604 = 604;
        float f605 = 605;
        double d605 = 605;
        float f606 = 606;
        double d606 = 606;
        float f607 = 607;
        double d607 = 607;
        float f608 = 608;
        double d608 = 608;
        float f609 = 609;
        double d609 = 609;
        float f610 = 610;
        double d610 = 610;
        float f611 = 611;
        double d611 = 611;
        float f612 = 612;
        double d612 = 612;
        float f613 = 613;
        double d613 = 613;
        float f614 = 614;
        double d614 = 614;
        float f615 = 615;
        double d615 = 615;
        float f616 = 616;
        double d616 = 616;
        float f617 = 617;
        double d617 = 617;
        float f618 = 618;
        double d618 = 618;
        float f619 = 619;
        double d619 = 619;
        float f620 = 620;
        double d620 = 620;
        float f621 = 621;
        double d621 = 621;
        float f622 = 622;
        double d622 = 622;
        float f623 = 623;
        double d623 = 623;
        float f624 = 624;
        double d624 = 624;
        float f625 = 625;
        double d625 = 625;
        float f626 = 626;
        double d626 = 626;
        float f627 = 627;
        double d627 = 627;
        float f628 = 628;
        double d628 = 628;
        float f629 = 629;
        double d629 = 629;
        float f630 = 630;
        double d630 = 630;
        float f631 = 631;
        double d631 = 631;
        float f632 = 632;
        double d632 = 632;
        float f633 = 633;
        double d633 = 633;
        float f634 = 634;
        double d634 = 634;
        float f635 = 635;
        double d635 = 635;
        float f636 = 636;
        double d636 = 636;
        float f637 = 637;
        double d637 = 637;
        float f638 = 638;
        double d638 = 638;
        float f639 = 639;
        double d639 = 639;
        float f640 = 640;
        double d640 = 640;
        float f641 = 641;
        double d641 = 641;
        float f642 = 642;
        double d642 = 642;
        float f643 = 643;
        double d643 = 643;
        float f644 = 644;
        double d644 = 644;
        float f645 = 645;
        double d645 = 645;
        float f646 = 646;
        double d646 = 646;
        float f647 = 647;
        double d647 = 647;
        float f648 = 648;
        double d648 = 648;
        float f649 = 649;
        double d649 = 649;
        float f650 = 650;
        double d650 = 650;
        float f651 = 651;
        double d651 = 651;
        float f652 = 652;
        double d652 = 652;
        float f653 = 653;
        double d653 = 653;
        float f654 = 654;
        double d654 = 654;
        float f655 = 655;
        double d655 = 655;
        float f656 = 656;
        double d656 = 656;
        float f657 = 657;
        double d657 = 657;
        float f658 = 658;
        double d658 = 658;
        float f659 = 659;
        double d659 = 659;
        float f660 = 660;
        double d660 = 660;
        float f661 = 661;
        double d661 = 661;
        float f662 = 662;
        double d662 = 662;
        float f663 = 663;
        double d663 = 663;
        float f664 = 664;
        double d664 = 664;
        float f665 = 665;
        double d665 = 665;
        float f666 = 666;
        double d666 = 666;
        float f667 = 667;
        double d667 = 667;
        float f668 = 668;
        double d668 = 668;
        float f669 = 669;
        double d669 = 669;
        float f670 = 670;
        double d670 = 670;
        float f671 = 671;
        double d671 = 671;
        float f672 = 672;
        double d672 = 672;
        float f673 = 673;
        double d673 = 673;
        float f674 = 674;
        double d674 = 674;
        float f675 = 675;
        double d675 = 675;
        float f676 = 676;
        double d676 = 676;
        float f677 = 677;
        double d677 = 677;
        float f678 = 678;
        double d678 = 678;
        float f679 = 679;
        double d679 = 679;
        float f680 = 680;
        double d680 = 680;
        float f681 = 681;
        double d681 = 681;
        float f682 = 682;
        double d682 = 682;
        float f683 = 683;
        double d683 = 683;
        float f684 = 684;
        double d684 = 684;
        float f685 = 685;
        double d685 = 685;
        float f686 = 686;
        double d686 = 686;
        float f687 = 687;
        double d687 = 687;
        float f688 = 688;
        double d688 = 688;
        float f689 = 689;
        double d689 = 689;
        float f690 = 690;
        double d690 = 690;
        float f691 = 691;
        double d691 = 691;
        float f692 = 692;
        double d692 = 692;
        float f693 = 693;
        double d693 = 693;
        float f694 = 694;
        double d694 = 694;
        float f695 = 695;
        double d695 = 695;
        float f696 = 696;
        double d696 = 696;
        float f697 = 697;
        double d697 = 697;
        float f698 = 698;
        double d698 = 698;
        float f699 = 699;
        double d699 = 699;
        float f700 = 700;
        double d700 = 700;
        float f701 = 701;
        double d701 = 701;
        float f702 = 702;
        double d702 = 702;
        float f703 = 703;
        double d703 = 703;
        float f704 = 704;
        double d704 = 704;
        float f705 = 705;
        double d705 = 705;
        float f706 = 706;
        double d706 = 706;
        float f707 = 707;
        double d707 = 707;
        float f708 = 708;
        double d708 = 708;
        float f709 = 709;
        double d709 = 709;
        float f710 = 710;
        double d710 = 710;
        float f711 = 711;
        double d711 = 711;
        float f712 = 712;
        double d712 = 712;
        float f713 = 713;
        double d713 = 713;
        float f714 = 714;
        double d714 = 714;
        float f715 = 715;
        double d715 = 715;
        float f716 = 716;
        double d716 = 716;
        float f717 = 717;
        double d717 = 717;
        float f718 = 718;
        double d718 = 718;
        float f719 = 719;
        double d719 = 719;
        float f720 = 720;
        double d720 = 720;
        float f721 = 721;
        double d721 = 721;
        float f722 = 722;
        double d722 = 722;
        float f723 = 723;
        double d723 = 723;
        float f724 = 724;
        double d724 = 724;
        float f725 = 725;
        double d725 = 725;
        float f726 = 726;
        double d726 = 726;
        float f727 = 727;
        double d727 = 727;
        float f728 = 728;
        double d728 = 728;
        float f729 = 729;
        double d729 = 729;
        float f730 = 730;
        double d730 = 730;
        float f731 = 731;
        double d731 = 731;
        float f732 = 732;
        double d732 = 732;
        float f733 = 733;
        double d733 = 733;
        float f734 = 734;
        double d734 = 734;
        float f735 = 735;
        double d735 = 735;
        float f736 = 736;
        double d736 = 736;
        float f737 = 737;
        double d737 = 737;
        float f738 = 738;
        double d738 = 738;
        float f739 = 739;
        double d739 = 739;
        float f740 = 740;
        double d740 = 740;
        float f741 = 741;
        double d741 = 741;
        float f742 = 742;
        double d742 = 742;
        float f743 = 743;
        double d743 = 743;
        float f744 = 744;
        double d744 = 744;
        float f745 = 745;
        double d745 = 745;
        float f746 = 746;
        double d746 = 746;
        float f747 = 747;
        double d747 = 747;
        float f748 = 748;
        double d748 = 748;
        float f749 = 749;
        double d749 = 749;
        float f750 = 750;
        double d750 = 750;
        float f751 = 751;
        double d751 = 751;
        float f752 = 752;
        double d752 = 752;
        float f753 = 753;
        double d753 = 753;
        float f754 = 754;
        double d754 = 754;
        float f755 = 755;
        double d755 = 755;
        float f756 = 756;
        double d756 = 756;
        float f757 = 757;
        double d757 = 757;
        float f758 = 758;
        double d758 = 758;
        float f759 = 759;
        double d759 = 759;
        float f760 = 760;
        double d760 = 760;
        float f761 = 761;
        double d761 = 761;
        float f762 = 762;
        double d762 = 762;
        float f763 = 763;
        double d763 = 763;
        float f764 = 764;
        double d764 = 764;
        float f765 = 765;
        double d765 = 765;
        float f766 = 766;
        double d766 = 766;
        float f767 = 767;
        double d767 = 767;
        float f768 = 768;
        double d768 = 768;
        float f769 = 769;
        double d769 = 769;
        float f770 = 770;
        double d770 = 770;
        float f771 = 771;
        double d771 = 771;
        float f772 = 772;
        double d772 = 772;
        float f773 = 773;
        double d773 = 773;
        float f774 = 774;
        double d774 = 774;
        float f775 = 775;
        double d775 = 775;
        float f776 = 776;
        double d776 = 776;
        float f777 = 777;
        double d777 = 777;
        float f778 = 778;
        double d778 = 778;
        float f779 = 779;
        double d779 = 779;
        float f780 = 780;
        double d780 = 780;
        float f781 = 781;
        double d781 = 781;
        float f782 = 782;
        double d782 = 782;
        float f783 = 783;
        double d783 = 783;
        float f784 = 784;
        double d784 = 784;
        float f785 = 785;
        double d785 = 785;
        float f786 = 786;
        double d786 = 786;
        float f787 = 787;
        double d787 = 787;
        float f788 = 788;
        double d788 = 788;
        float f789 = 789;
        double d789 = 789;
        float f790 = 790;
        double d790 = 790;
        float f791 = 791;
        double d791 = 791;
        float f792 = 792;
        double d792 = 792;
        float f793 = 793;
        double d793 = 793;
        float f794 = 794;
        double d794 = 794;
        float f795 = 795;
        double d795 = 795;
        float f796 = 796;
        double d796 = 796;
        float f797 = 797;
        double d797 = 797;
        float f798 = 798;
        double d798 = 798;
        float f799 = 799;
        double d799 = 799;
        float f800 = 800;
        double d800 = 800;
        float f801 = 801;
        double d801 = 801;
        float f802 = 802;
        double d802 = 802;
        float f803 = 803;
        double d803 = 803;
        float f804 = 804;
        double d804 = 804;
        float f805 = 805;
        double d805 = 805;
        float f806 = 806;
        double d806 = 806;
        float f807 = 807;
        double d807 = 807;
        float f808 = 808;
        double d808 = 808;
        float f809 = 809;
        double d809 = 809;
        float f810 = 810;
        double d810 = 810;
        float f811 = 811;
        double d811 = 811;
        float f812 = 812;
        double d812 = 812;
        float f813 = 813;
        double d813 = 813;
        float f814 = 814;
        double d814 = 814;
        float f815 = 815;
        double d815 = 815;
        float f816 = 816;
        double d816 = 816;
        float f817 = 817;
        double d817 = 817;
        float f818 = 818;
        double d818 = 818;
        float f819 = 819;
        double d819 = 819;
        float f820 = 820;
        double d820 = 820;
        float f821 = 821;
        double d821 = 821;
        float f822 = 822;
        double d822 = 822;
        float f823 = 823;
        double d823 = 823;
        float f824 = 824;
        double d824 = 824;
        float f825 = 825;
        double d825 = 825;
        float f826 = 826;
        double d826 = 826;
        float f827 = 827;
        double d827 = 827;
        float f828 = 828;
        double d828 = 828;
        float f829 = 829;
        double d829 = 829;
        float f830 = 830;
        double d830 = 830;
        float f831 = 831;
        double d831 = 831;
        float f832 = 832;
        double d832 = 832;
        float f833 = 833;
        double d833 = 833;
        float f834 = 834;
        double d834 = 834;
        float f835 = 835;
        double d835 = 835;
        float f836 = 836;
        double d836 = 836;
        float f837 = 837;
        double d837 = 837;
        float f838 = 838;
        double d838 = 838;
        float f839 = 839;
        double d839 = 839;
        float f840 = 840;
        double d840 = 840;
        float f841 = 841;
        double d841 = 841;
        float f842 = 842;
        double d842 = 842;
        float f843 = 843;
        double d843 = 843;
        float f844 = 844;
        double d844 = 844;
        float f845 = 845;
        double d845 = 845;
        float f846 = 846;
        double d846 = 846;
        float f847 = 847;
        double d847 = 847;
        float f848 = 848;
        double d848 = 848;
        float f849 = 849;
        double d849 = 849;
        float f850 = 850;
        double d850 = 850;
        float f851 = 851;
        double d851 = 851;
        float f852 = 852;
        double d852 = 852;
        float f853 = 853;
        double d853 = 853;
        float f854 = 854;
        double d854 = 854;
        float f855 = 855;
        double d855 = 855;
        float f856 = 856;
        double d856 = 856;
        float f857 = 857;
        double d857 = 857;
        float f858 = 858;
        double d858 = 858;
        float f859 = 859;
        double d859 = 859;
        float f860 = 860;
        double d860 = 860;
        float f861 = 861;
        double d861 = 861;
        float f862 = 862;
        double d862 = 862;
        float f863 = 863;
        double d863 = 863;
        float f864 = 864;
        double d864 = 864;
        float f865 = 865;
        double d865 = 865;
        float f866 = 866;
        double d866 = 866;
        float f867 = 867;
        double d867 = 867;
        float f868 = 868;
        double d868 = 868;
        float f869 = 869;
        double d869 = 869;
        float f870 = 870;
        double d870 = 870;
        float f871 = 871;
        double d871 = 871;
        float f872 = 872;
        double d872 = 872;
        float f873 = 873;
        double d873 = 873;
        float f874 = 874;
        double d874 = 874;
        float f875 = 875;
        double d875 = 875;
        float f876 = 876;
        double d876 = 876;
        float f877 = 877;
        double d877 = 877;
        float f878 = 878;
        double d878 = 878;
        float f879 = 879;
        double d879 = 879;
        float f880 = 880;
        double d880 = 880;
        float f881 = 881;
        double d881 = 881;
        float f882 = 882;
        double d882 = 882;
        float f883 = 883;
        double d883 = 883;
        float f884 = 884;
        double d884 = 884;
        float f885 = 885;
        double d885 = 885;
        float f886 = 886;
        double d886 = 886;
        float f887 = 887;
        double d887 = 887;
        float f888 = 888;
        double d888 = 888;
        float f889 = 889;
        double d889 = 889;
        float f890 = 890;
        double d890 = 890;
        float f891 = 891;
        double d891 = 891;
        float f892 = 892;
        double d892 = 892;
        float f893 = 893;
        double d893 = 893;
        float f894 = 894;
        double d894 = 894;
        float f895 = 895;
        double d895 = 895;
        float f896 = 896;
        double d896 = 896;
        float f897 = 897;
        double d897 = 897;
        float f898 = 898;
        double d898 = 898;
        float f899 = 899;
        double d899 = 899;
        float f900 = 900;
        double d900 = 900;
        float f901 = 901;
        double d901 = 901;
        float f902 = 902;
        double d902 = 902;
        float f903 = 903;
        double d903 = 903;
        float f904 = 904;
        double d904 = 904;
        float f905 = 905;
        double d905 = 905;
        float f906 = 906;
        double d906 = 906;
        float f907 = 907;
        double d907 = 907;
        float f908 = 908;
        double d908 = 908;
        float f909 = 909;
        double d909 = 909;
        float f910 = 910;
        double d910 = 910;
        float f911 = 911;
        double d911 = 911;
        float f912 = 912;
        double d912 = 912;
        float f913 = 913;
        double d913 = 913;
        float f914 = 914;
        double d914 = 914;
        float f915 = 915;
        double d915 = 915;
        float f916 = 916;
        double d916 = 916;
        float f917 = 917;
        double d917 = 917;
        float f918 = 918;
        double d918 = 918;
        float f919 = 919;
        double d919 = 919;
        float f920 = 920;
        double d920 = 920;
        float f921 = 921;
        double d921 = 921;
        float f922 = 922;
        double d922 = 922;
        float f923 = 923;
        double d923 = 923;
        float f924 = 924;
        double d924 = 924;
        float f925 = 925;
        double d925 = 925;
        float f926 = 926;
        double d926 = 926;
        float f927 = 927;
        double d927 = 927;
        float f928 = 928;
        double d928 = 928;
        float f929 = 929;
        double d929 = 929;
        float f930 = 930;
        double d930 = 930;
        float f931 = 931;
        double d931 = 931;
        float f932 = 932;
        double d932 = 932;
        float f933 = 933;
        double d933 = 933;
        float f934 = 934;
        double d934 = 934;
        float f935 = 935;
        double d935 = 935;
        float f936 = 936;
        double d936 = 936;
        float f937 = 937;
        double d937 = 937;
        float f938 = 938;
        double d938 = 938;
        float f939 = 939;
        double d939 = 939;
        float f940 = 940;
        double d940 = 940;
        float f941 = 941;
        double d941 = 941;
        float f942 = 942;
        double d942 = 942;
        float f943 = 943;
        double d943 = 943;
        float f944 = 944;
        double d944 = 944;
        float f945 = 945;
        double d945 = 945;
        float f946 = 946;
        double d946 = 946;
        float f947 = 947;
        double d947 = 947;
        float f948 = 948;
        double d948 = 948;
        float f949 = 949;
        double d949 = 949;
        float f950 = 950;
        double d950 = 950;
        float f951 = 951;
        double d951 = 951;
        float f952 = 952;
        double d952 = 952;
        float f953 = 953;
        double d953 = 953;
        float f954 = 954;
        double d954 = 954;
        float f955 = 955;
        double d955 = 955;
        float f956 = 956;
        double d956 = 956;
        float f957 = 957;
        double d957 = 957;
        float f958 = 958;
        double d958 = 958;
        float f959 = 959;
        double d959 = 959;
        float f960 = 960;
        double d960 = 960;
        float f961 = 961;
        double d961 = 961;
        float f962 = 962;
        double d962 = 962;
        float f963 = 963;
        double d963 = 963;
        float f964 = 964;
        double d964 = 964;
        float f965 = 965;
        double d965 = 965;
        float f966 = 966;
        double d966 = 966;
        float f967 = 967;
        double d967 = 967;
        float f968 = 968;
        double d968 = 968;
        float f969 = 969;
        double d969 = 969;
        float f970 = 970;
        double d970 = 970;
        float f971 = 971;
        double d971 = 971;
        float f972 = 972;
        double d972 = 972;
        float f973 = 973;
        double d973 = 973;
        float f974 = 974;
        double d974 = 974;
        float f975 = 975;
        double d975 = 975;
        float f976 = 976;
        double d976 = 976;
        float f977 = 977;
        double d977 = 977;
        float f978 = 978;
        double d978 = 978;
        float f979 = 979;
        double d979 = 979;
        float f980 = 980;
        double d980 = 980;
        float f981 = 981;
        double d981 = 981;
        float f982 = 982;
        double d982 = 982;
        float f983 = 983;
        double d983 = 983;
        float f984 = 984;
        double d984 = 984;
        float f985 = 985;
        double d985 = 985;
        float f986 = 986;
        double d986 = 986;
        float f987 = 987;
        double d987 = 987;
        float f988 = 988;
        double d988 = 988;
        float f989 = 989;
        double d989 = 989;
        float f990 = 990;
        double d990 = 990;
        float f991 = 991;
        double d991 = 991;
        float f992 = 992;
        double d992 = 992;
        float f993 = 993;
        double d993 = 993;
        float f994 = 994;
        double d994 = 994;
        float f995 = 995;
        double d995 = 995;
        float f996 = 996;
        double d996 = 996;
        float f997 = 997;
        double d997 = 997;
        float f998 = 998;
        double d998 = 998;
        float f999 = 999;
        double d999 = 999;
        f1 += f0;
        d1 = d0;
        f2 += f1;
        d2 = d1;
        f3 += f2;
        d3 = d2;
        f4 += f3;
        d4 = d3;
        f5 += f4;
        d5 = d4;
        f6 += f5;
        d6 = d5;
        f7 += f6;
        d7 = d6;
        f8 += f7;
        d8 = d7;
        f9 += f8;
        d9 = d8;
        f10 += f9;
        d10 = d9;
        f11 += f10;
        d11 = d10;
        f12 += f11;
        d12 = d11;
        f13 += f12;
        d13 = d12;
        f14 += f13;
        d14 = d13;
        f15 += f14;
        d15 = d14;
        f16 += f15;
        d16 = d15;
        f17 += f16;
        d17 = d16;
        f18 += f17;
        d18 = d17;
        f19 += f18;
        d19 = d18;
        f20 += f19;
        d20 = d19;
        f21 += f20;
        d21 = d20;
        f22 += f21;
        d22 = d21;
        f23 += f22;
        d23 = d22;
        f24 += f23;
        d24 = d23;
        f25 += f24;
        d25 = d24;
        f26 += f25;
        d26 = d25;
        f27 += f26;
        d27 = d26;
        f28 += f27;
        d28 = d27;
        f29 += f28;
        d29 = d28;
        f30 += f29;
        d30 = d29;
        f31 += f30;
        d31 = d30;
        f32 += f31;
        d32 = d31;
        f33 += f32;
        d33 = d32;
        f34 += f33;
        d34 = d33;
        f35 += f34;
        d35 = d34;
        f36 += f35;
        d36 = d35;
        f37 += f36;
        d37 = d36;
        f38 += f37;
        d38 = d37;
        f39 += f38;
        d39 = d38;
        f40 += f39;
        d40 = d39;
        f41 += f40;
        d41 = d40;
        f42 += f41;
        d42 = d41;
        f43 += f42;
        d43 = d42;
        f44 += f43;
        d44 = d43;
        f45 += f44;
        d45 = d44;
        f46 += f45;
        d46 = d45;
        f47 += f46;
        d47 = d46;
        f48 += f47;
        d48 = d47;
        f49 += f48;
        d49 = d48;
        f50 += f49;
        d50 = d49;
        f51 += f50;
        d51 = d50;
        f52 += f51;
        d52 = d51;
        f53 += f52;
        d53 = d52;
        f54 += f53;
        d54 = d53;
        f55 += f54;
        d55 = d54;
        f56 += f55;
        d56 = d55;
        f57 += f56;
        d57 = d56;
        f58 += f57;
        d58 = d57;
        f59 += f58;
        d59 = d58;
        f60 += f59;
        d60 = d59;
        f61 += f60;
        d61 = d60;
        f62 += f61;
        d62 = d61;
        f63 += f62;
        d63 = d62;
        f64 += f63;
        d64 = d63;
        f65 += f64;
        d65 = d64;
        f66 += f65;
        d66 = d65;
        f67 += f66;
        d67 = d66;
        f68 += f67;
        d68 = d67;
        f69 += f68;
        d69 = d68;
        f70 += f69;
        d70 = d69;
        f71 += f70;
        d71 = d70;
        f72 += f71;
        d72 = d71;
        f73 += f72;
        d73 = d72;
        f74 += f73;
        d74 = d73;
        f75 += f74;
        d75 = d74;
        f76 += f75;
        d76 = d75;
        f77 += f76;
        d77 = d76;
        f78 += f77;
        d78 = d77;
        f79 += f78;
        d79 = d78;
        f80 += f79;
        d80 = d79;
        f81 += f80;
        d81 = d80;
        f82 += f81;
        d82 = d81;
        f83 += f82;
        d83 = d82;
        f84 += f83;
        d84 = d83;
        f85 += f84;
        d85 = d84;
        f86 += f85;
        d86 = d85;
        f87 += f86;
        d87 = d86;
        f88 += f87;
        d88 = d87;
        f89 += f88;
        d89 = d88;
        f90 += f89;
        d90 = d89;
        f91 += f90;
        d91 = d90;
        f92 += f91;
        d92 = d91;
        f93 += f92;
        d93 = d92;
        f94 += f93;
        d94 = d93;
        f95 += f94;
        d95 = d94;
        f96 += f95;
        d96 = d95;
        f97 += f96;
        d97 = d96;
        f98 += f97;
        d98 = d97;
        f99 += f98;
        d99 = d98;
        f100 += f99;
        d100 = d99;
        f101 += f100;
        d101 = d100;
        f102 += f101;
        d102 = d101;
        f103 += f102;
        d103 = d102;
        f104 += f103;
        d104 = d103;
        f105 += f104;
        d105 = d104;
        f106 += f105;
        d106 = d105;
        f107 += f106;
        d107 = d106;
        f108 += f107;
        d108 = d107;
        f109 += f108;
        d109 = d108;
        f110 += f109;
        d110 = d109;
        f111 += f110;
        d111 = d110;
        f112 += f111;
        d112 = d111;
        f113 += f112;
        d113 = d112;
        f114 += f113;
        d114 = d113;
        f115 += f114;
        d115 = d114;
        f116 += f115;
        d116 = d115;
        f117 += f116;
        d117 = d116;
        f118 += f117;
        d118 = d117;
        f119 += f118;
        d119 = d118;
        f120 += f119;
        d120 = d119;
        f121 += f120;
        d121 = d120;
        f122 += f121;
        d122 = d121;
        f123 += f122;
        d123 = d122;
        f124 += f123;
        d124 = d123;
        f125 += f124;
        d125 = d124;
        f126 += f125;
        d126 = d125;
        f127 += f126;
        d127 = d126;
        f128 += f127;
        d128 = d127;
        f129 += f128;
        d129 = d128;
        f130 += f129;
        d130 = d129;
        f131 += f130;
        d131 = d130;
        f132 += f131;
        d132 = d131;
        f133 += f132;
        d133 = d132;
        f134 += f133;
        d134 = d133;
        f135 += f134;
        d135 = d134;
        f136 += f135;
        d136 = d135;
        f137 += f136;
        d137 = d136;
        f138 += f137;
        d138 = d137;
        f139 += f138;
        d139 = d138;
        f140 += f139;
        d140 = d139;
        f141 += f140;
        d141 = d140;
        f142 += f141;
        d142 = d141;
        f143 += f142;
        d143 = d142;
        f144 += f143;
        d144 = d143;
        f145 += f144;
        d145 = d144;
        f146 += f145;
        d146 = d145;
        f147 += f146;
        d147 = d146;
        f148 += f147;
        d148 = d147;
        f149 += f148;
        d149 = d148;
        f150 += f149;
        d150 = d149;
        f151 += f150;
        d151 = d150;
        f152 += f151;
        d152 = d151;
        f153 += f152;
        d153 = d152;
        f154 += f153;
        d154 = d153;
        f155 += f154;
        d155 = d154;
        f156 += f155;
        d156 = d155;
        f157 += f156;
        d157 = d156;
        f158 += f157;
        d158 = d157;
        f159 += f158;
        d159 = d158;
        f160 += f159;
        d160 = d159;
        f161 += f160;
        d161 = d160;
        f162 += f161;
        d162 = d161;
        f163 += f162;
        d163 = d162;
        f164 += f163;
        d164 = d163;
        f165 += f164;
        d165 = d164;
        f166 += f165;
        d166 = d165;
        f167 += f166;
        d167 = d166;
        f168 += f167;
        d168 = d167;
        f169 += f168;
        d169 = d168;
        f170 += f169;
        d170 = d169;
        f171 += f170;
        d171 = d170;
        f172 += f171;
        d172 = d171;
        f173 += f172;
        d173 = d172;
        f174 += f173;
        d174 = d173;
        f175 += f174;
        d175 = d174;
        f176 += f175;
        d176 = d175;
        f177 += f176;
        d177 = d176;
        f178 += f177;
        d178 = d177;
        f179 += f178;
        d179 = d178;
        f180 += f179;
        d180 = d179;
        f181 += f180;
        d181 = d180;
        f182 += f181;
        d182 = d181;
        f183 += f182;
        d183 = d182;
        f184 += f183;
        d184 = d183;
        f185 += f184;
        d185 = d184;
        f186 += f185;
        d186 = d185;
        f187 += f186;
        d187 = d186;
        f188 += f187;
        d188 = d187;
        f189 += f188;
        d189 = d188;
        f190 += f189;
        d190 = d189;
        f191 += f190;
        d191 = d190;
        f192 += f191;
        d192 = d191;
        f193 += f192;
        d193 = d192;
        f194 += f193;
        d194 = d193;
        f195 += f194;
        d195 = d194;
        f196 += f195;
        d196 = d195;
        f197 += f196;
        d197 = d196;
        f198 += f197;
        d198 = d197;
        f199 += f198;
        d199 = d198;
        f200 += f199;
        d200 = d199;
        f201 += f200;
        d201 = d200;
        f202 += f201;
        d202 = d201;
        f203 += f202;
        d203 = d202;
        f204 += f203;
        d204 = d203;
        f205 += f204;
        d205 = d204;
        f206 += f205;
        d206 = d205;
        f207 += f206;
        d207 = d206;
        f208 += f207;
        d208 = d207;
        f209 += f208;
        d209 = d208;
        f210 += f209;
        d210 = d209;
        f211 += f210;
        d211 = d210;
        f212 += f211;
        d212 = d211;
        f213 += f212;
        d213 = d212;
        f214 += f213;
        d214 = d213;
        f215 += f214;
        d215 = d214;
        f216 += f215;
        d216 = d215;
        f217 += f216;
        d217 = d216;
        f218 += f217;
        d218 = d217;
        f219 += f218;
        d219 = d218;
        f220 += f219;
        d220 = d219;
        f221 += f220;
        d221 = d220;
        f222 += f221;
        d222 = d221;
        f223 += f222;
        d223 = d222;
        f224 += f223;
        d224 = d223;
        f225 += f224;
        d225 = d224;
        f226 += f225;
        d226 = d225;
        f227 += f226;
        d227 = d226;
        f228 += f227;
        d228 = d227;
        f229 += f228;
        d229 = d228;
        f230 += f229;
        d230 = d229;
        f231 += f230;
        d231 = d230;
        f232 += f231;
        d232 = d231;
        f233 += f232;
        d233 = d232;
        f234 += f233;
        d234 = d233;
        f235 += f234;
        d235 = d234;
        f236 += f235;
        d236 = d235;
        f237 += f236;
        d237 = d236;
        f238 += f237;
        d238 = d237;
        f239 += f238;
        d239 = d238;
        f240 += f239;
        d240 = d239;
        f241 += f240;
        d241 = d240;
        f242 += f241;
        d242 = d241;
        f243 += f242;
        d243 = d242;
        f244 += f243;
        d244 = d243;
        f245 += f244;
        d245 = d244;
        f246 += f245;
        d246 = d245;
        f247 += f246;
        d247 = d246;
        f248 += f247;
        d248 = d247;
        f249 += f248;
        d249 = d248;
        f250 += f249;
        d250 = d249;
        f251 += f250;
        d251 = d250;
        f252 += f251;
        d252 = d251;
        f253 += f252;
        d253 = d252;
        f254 += f253;
        d254 = d253;
        f255 += f254;
        d255 = d254;
        f256 += f255;
        d256 = d255;
        f257 += f256;
        d257 = d256;
        f258 += f257;
        d258 = d257;
        f259 += f258;
        d259 = d258;
        f260 += f259;
        d260 = d259;
        f261 += f260;
        d261 = d260;
        f262 += f261;
        d262 = d261;
        f263 += f262;
        d263 = d262;
        f264 += f263;
        d264 = d263;
        f265 += f264;
        d265 = d264;
        f266 += f265;
        d266 = d265;
        f267 += f266;
        d267 = d266;
        f268 += f267;
        d268 = d267;
        f269 += f268;
        d269 = d268;
        f270 += f269;
        d270 = d269;
        f271 += f270;
        d271 = d270;
        f272 += f271;
        d272 = d271;
        f273 += f272;
        d273 = d272;
        f274 += f273;
        d274 = d273;
        f275 += f274;
        d275 = d274;
        f276 += f275;
        d276 = d275;
        f277 += f276;
        d277 = d276;
        f278 += f277;
        d278 = d277;
        f279 += f278;
        d279 = d278;
        f280 += f279;
        d280 = d279;
        f281 += f280;
        d281 = d280;
        f282 += f281;
        d282 = d281;
        f283 += f282;
        d283 = d282;
        f284 += f283;
        d284 = d283;
        f285 += f284;
        d285 = d284;
        f286 += f285;
        d286 = d285;
        f287 += f286;
        d287 = d286;
        f288 += f287;
        d288 = d287;
        f289 += f288;
        d289 = d288;
        f290 += f289;
        d290 = d289;
        f291 += f290;
        d291 = d290;
        f292 += f291;
        d292 = d291;
        f293 += f292;
        d293 = d292;
        f294 += f293;
        d294 = d293;
        f295 += f294;
        d295 = d294;
        f296 += f295;
        d296 = d295;
        f297 += f296;
        d297 = d296;
        f298 += f297;
        d298 = d297;
        f299 += f298;
        d299 = d298;
        f300 += f299;
        d300 = d299;
        f301 += f300;
        d301 = d300;
        f302 += f301;
        d302 = d301;
        f303 += f302;
        d303 = d302;
        f304 += f303;
        d304 = d303;
        f305 += f304;
        d305 = d304;
        f306 += f305;
        d306 = d305;
        f307 += f306;
        d307 = d306;
        f308 += f307;
        d308 = d307;
        f309 += f308;
        d309 = d308;
        f310 += f309;
        d310 = d309;
        f311 += f310;
        d311 = d310;
        f312 += f311;
        d312 = d311;
        f313 += f312;
        d313 = d312;
        f314 += f313;
        d314 = d313;
        f315 += f314;
        d315 = d314;
        f316 += f315;
        d316 = d315;
        f317 += f316;
        d317 = d316;
        f318 += f317;
        d318 = d317;
        f319 += f318;
        d319 = d318;
        f320 += f319;
        d320 = d319;
        f321 += f320;
        d321 = d320;
        f322 += f321;
        d322 = d321;
        f323 += f322;
        d323 = d322;
        f324 += f323;
        d324 = d323;
        f325 += f324;
        d325 = d324;
        f326 += f325;
        d326 = d325;
        f327 += f326;
        d327 = d326;
        f328 += f327;
        d328 = d327;
        f329 += f328;
        d329 = d328;
        f330 += f329;
        d330 = d329;
        f331 += f330;
        d331 = d330;
        f332 += f331;
        d332 = d331;
        f333 += f332;
        d333 = d332;
        f334 += f333;
        d334 = d333;
        f335 += f334;
        d335 = d334;
        f336 += f335;
        d336 = d335;
        f337 += f336;
        d337 = d336;
        f338 += f337;
        d338 = d337;
        f339 += f338;
        d339 = d338;
        f340 += f339;
        d340 = d339;
        f341 += f340;
        d341 = d340;
        f342 += f341;
        d342 = d341;
        f343 += f342;
        d343 = d342;
        f344 += f343;
        d344 = d343;
        f345 += f344;
        d345 = d344;
        f346 += f345;
        d346 = d345;
        f347 += f346;
        d347 = d346;
        f348 += f347;
        d348 = d347;
        f349 += f348;
        d349 = d348;
        f350 += f349;
        d350 = d349;
        f351 += f350;
        d351 = d350;
        f352 += f351;
        d352 = d351;
        f353 += f352;
        d353 = d352;
        f354 += f353;
        d354 = d353;
        f355 += f354;
        d355 = d354;
        f356 += f355;
        d356 = d355;
        f357 += f356;
        d357 = d356;
        f358 += f357;
        d358 = d357;
        f359 += f358;
        d359 = d358;
        f360 += f359;
        d360 = d359;
        f361 += f360;
        d361 = d360;
        f362 += f361;
        d362 = d361;
        f363 += f362;
        d363 = d362;
        f364 += f363;
        d364 = d363;
        f365 += f364;
        d365 = d364;
        f366 += f365;
        d366 = d365;
        f367 += f366;
        d367 = d366;
        f368 += f367;
        d368 = d367;
        f369 += f368;
        d369 = d368;
        f370 += f369;
        d370 = d369;
        f371 += f370;
        d371 = d370;
        f372 += f371;
        d372 = d371;
        f373 += f372;
        d373 = d372;
        f374 += f373;
        d374 = d373;
        f375 += f374;
        d375 = d374;
        f376 += f375;
        d376 = d375;
        f377 += f376;
        d377 = d376;
        f378 += f377;
        d378 = d377;
        f379 += f378;
        d379 = d378;
        f380 += f379;
        d380 = d379;
        f381 += f380;
        d381 = d380;
        f382 += f381;
        d382 = d381;
        f383 += f382;
        d383 = d382;
        f384 += f383;
        d384 = d383;
        f385 += f384;
        d385 = d384;
        f386 += f385;
        d386 = d385;
        f387 += f386;
        d387 = d386;
        f388 += f387;
        d388 = d387;
        f389 += f388;
        d389 = d388;
        f390 += f389;
        d390 = d389;
        f391 += f390;
        d391 = d390;
        f392 += f391;
        d392 = d391;
        f393 += f392;
        d393 = d392;
        f394 += f393;
        d394 = d393;
        f395 += f394;
        d395 = d394;
        f396 += f395;
        d396 = d395;
        f397 += f396;
        d397 = d396;
        f398 += f397;
        d398 = d397;
        f399 += f398;
        d399 = d398;
        f400 += f399;
        d400 = d399;
        f401 += f400;
        d401 = d400;
        f402 += f401;
        d402 = d401;
        f403 += f402;
        d403 = d402;
        f404 += f403;
        d404 = d403;
        f405 += f404;
        d405 = d404;
        f406 += f405;
        d406 = d405;
        f407 += f406;
        d407 = d406;
        f408 += f407;
        d408 = d407;
        f409 += f408;
        d409 = d408;
        f410 += f409;
        d410 = d409;
        f411 += f410;
        d411 = d410;
        f412 += f411;
        d412 = d411;
        f413 += f412;
        d413 = d412;
        f414 += f413;
        d414 = d413;
        f415 += f414;
        d415 = d414;
        f416 += f415;
        d416 = d415;
        f417 += f416;
        d417 = d416;
        f418 += f417;
        d418 = d417;
        f419 += f418;
        d419 = d418;
        f420 += f419;
        d420 = d419;
        f421 += f420;
        d421 = d420;
        f422 += f421;
        d422 = d421;
        f423 += f422;
        d423 = d422;
        f424 += f423;
        d424 = d423;
        f425 += f424;
        d425 = d424;
        f426 += f425;
        d426 = d425;
        f427 += f426;
        d427 = d426;
        f428 += f427;
        d428 = d427;
        f429 += f428;
        d429 = d428;
        f430 += f429;
        d430 = d429;
        f431 += f430;
        d431 = d430;
        f432 += f431;
        d432 = d431;
        f433 += f432;
        d433 = d432;
        f434 += f433;
        d434 = d433;
        f435 += f434;
        d435 = d434;
        f436 += f435;
        d436 = d435;
        f437 += f436;
        d437 = d436;
        f438 += f437;
        d438 = d437;
        f439 += f438;
        d439 = d438;
        f440 += f439;
        d440 = d439;
        f441 += f440;
        d441 = d440;
        f442 += f441;
        d442 = d441;
        f443 += f442;
        d443 = d442;
        f444 += f443;
        d444 = d443;
        f445 += f444;
        d445 = d444;
        f446 += f445;
        d446 = d445;
        f447 += f446;
        d447 = d446;
        f448 += f447;
        d448 = d447;
        f449 += f448;
        d449 = d448;
        f450 += f449;
        d450 = d449;
        f451 += f450;
        d451 = d450;
        f452 += f451;
        d452 = d451;
        f453 += f452;
        d453 = d452;
        f454 += f453;
        d454 = d453;
        f455 += f454;
        d455 = d454;
        f456 += f455;
        d456 = d455;
        f457 += f456;
        d457 = d456;
        f458 += f457;
        d458 = d457;
        f459 += f458;
        d459 = d458;
        f460 += f459;
        d460 = d459;
        f461 += f460;
        d461 = d460;
        f462 += f461;
        d462 = d461;
        f463 += f462;
        d463 = d462;
        f464 += f463;
        d464 = d463;
        f465 += f464;
        d465 = d464;
        f466 += f465;
        d466 = d465;
        f467 += f466;
        d467 = d466;
        f468 += f467;
        d468 = d467;
        f469 += f468;
        d469 = d468;
        f470 += f469;
        d470 = d469;
        f471 += f470;
        d471 = d470;
        f472 += f471;
        d472 = d471;
        f473 += f472;
        d473 = d472;
        f474 += f473;
        d474 = d473;
        f475 += f474;
        d475 = d474;
        f476 += f475;
        d476 = d475;
        f477 += f476;
        d477 = d476;
        f478 += f477;
        d478 = d477;
        f479 += f478;
        d479 = d478;
        f480 += f479;
        d480 = d479;
        f481 += f480;
        d481 = d480;
        f482 += f481;
        d482 = d481;
        f483 += f482;
        d483 = d482;
        f484 += f483;
        d484 = d483;
        f485 += f484;
        d485 = d484;
        f486 += f485;
        d486 = d485;
        f487 += f486;
        d487 = d486;
        f488 += f487;
        d488 = d487;
        f489 += f488;
        d489 = d488;
        f490 += f489;
        d490 = d489;
        f491 += f490;
        d491 = d490;
        f492 += f491;
        d492 = d491;
        f493 += f492;
        d493 = d492;
        f494 += f493;
        d494 = d493;
        f495 += f494;
        d495 = d494;
        f496 += f495;
        d496 = d495;
        f497 += f496;
        d497 = d496;
        f498 += f497;
        d498 = d497;
        f499 += f498;
        d499 = d498;
        f500 += f499;
        d500 = d499;
        f501 += f500;
        d501 = d500;
        f502 += f501;
        d502 = d501;
        f503 += f502;
        d503 = d502;
        f504 += f503;
        d504 = d503;
        f505 += f504;
        d505 = d504;
        f506 += f505;
        d506 = d505;
        f507 += f506;
        d507 = d506;
        f508 += f507;
        d508 = d507;
        f509 += f508;
        d509 = d508;
        f510 += f509;
        d510 = d509;
        f511 += f510;
        d511 = d510;
        f512 += f511;
        d512 = d511;
        f513 += f512;
        d513 = d512;
        f514 += f513;
        d514 = d513;
        f515 += f514;
        d515 = d514;
        f516 += f515;
        d516 = d515;
        f517 += f516;
        d517 = d516;
        f518 += f517;
        d518 = d517;
        f519 += f518;
        d519 = d518;
        f520 += f519;
        d520 = d519;
        f521 += f520;
        d521 = d520;
        f522 += f521;
        d522 = d521;
        f523 += f522;
        d523 = d522;
        f524 += f523;
        d524 = d523;
        f525 += f524;
        d525 = d524;
        f526 += f525;
        d526 = d525;
        f527 += f526;
        d527 = d526;
        f528 += f527;
        d528 = d527;
        f529 += f528;
        d529 = d528;
        f530 += f529;
        d530 = d529;
        f531 += f530;
        d531 = d530;
        f532 += f531;
        d532 = d531;
        f533 += f532;
        d533 = d532;
        f534 += f533;
        d534 = d533;
        f535 += f534;
        d535 = d534;
        f536 += f535;
        d536 = d535;
        f537 += f536;
        d537 = d536;
        f538 += f537;
        d538 = d537;
        f539 += f538;
        d539 = d538;
        f540 += f539;
        d540 = d539;
        f541 += f540;
        d541 = d540;
        f542 += f541;
        d542 = d541;
        f543 += f542;
        d543 = d542;
        f544 += f543;
        d544 = d543;
        f545 += f544;
        d545 = d544;
        f546 += f545;
        d546 = d545;
        f547 += f546;
        d547 = d546;
        f548 += f547;
        d548 = d547;
        f549 += f548;
        d549 = d548;
        f550 += f549;
        d550 = d549;
        f551 += f550;
        d551 = d550;
        f552 += f551;
        d552 = d551;
        f553 += f552;
        d553 = d552;
        f554 += f553;
        d554 = d553;
        f555 += f554;
        d555 = d554;
        f556 += f555;
        d556 = d555;
        f557 += f556;
        d557 = d556;
        f558 += f557;
        d558 = d557;
        f559 += f558;
        d559 = d558;
        f560 += f559;
        d560 = d559;
        f561 += f560;
        d561 = d560;
        f562 += f561;
        d562 = d561;
        f563 += f562;
        d563 = d562;
        f564 += f563;
        d564 = d563;
        f565 += f564;
        d565 = d564;
        f566 += f565;
        d566 = d565;
        f567 += f566;
        d567 = d566;
        f568 += f567;
        d568 = d567;
        f569 += f568;
        d569 = d568;
        f570 += f569;
        d570 = d569;
        f571 += f570;
        d571 = d570;
        f572 += f571;
        d572 = d571;
        f573 += f572;
        d573 = d572;
        f574 += f573;
        d574 = d573;
        f575 += f574;
        d575 = d574;
        f576 += f575;
        d576 = d575;
        f577 += f576;
        d577 = d576;
        f578 += f577;
        d578 = d577;
        f579 += f578;
        d579 = d578;
        f580 += f579;
        d580 = d579;
        f581 += f580;
        d581 = d580;
        f582 += f581;
        d582 = d581;
        f583 += f582;
        d583 = d582;
        f584 += f583;
        d584 = d583;
        f585 += f584;
        d585 = d584;
        f586 += f585;
        d586 = d585;
        f587 += f586;
        d587 = d586;
        f588 += f587;
        d588 = d587;
        f589 += f588;
        d589 = d588;
        f590 += f589;
        d590 = d589;
        f591 += f590;
        d591 = d590;
        f592 += f591;
        d592 = d591;
        f593 += f592;
        d593 = d592;
        f594 += f593;
        d594 = d593;
        f595 += f594;
        d595 = d594;
        f596 += f595;
        d596 = d595;
        f597 += f596;
        d597 = d596;
        f598 += f597;
        d598 = d597;
        f599 += f598;
        d599 = d598;
        f600 += f599;
        d600 = d599;
        f601 += f600;
        d601 = d600;
        f602 += f601;
        d602 = d601;
        f603 += f602;
        d603 = d602;
        f604 += f603;
        d604 = d603;
        f605 += f604;
        d605 = d604;
        f606 += f605;
        d606 = d605;
        f607 += f606;
        d607 = d606;
        f608 += f607;
        d608 = d607;
        f609 += f608;
        d609 = d608;
        f610 += f609;
        d610 = d609;
        f611 += f610;
        d611 = d610;
        f612 += f611;
        d612 = d611;
        f613 += f612;
        d613 = d612;
        f614 += f613;
        d614 = d613;
        f615 += f614;
        d615 = d614;
        f616 += f615;
        d616 = d615;
        f617 += f616;
        d617 = d616;
        f618 += f617;
        d618 = d617;
        f619 += f618;
        d619 = d618;
        f620 += f619;
        d620 = d619;
        f621 += f620;
        d621 = d620;
        f622 += f621;
        d622 = d621;
        f623 += f622;
        d623 = d622;
        f624 += f623;
        d624 = d623;
        f625 += f624;
        d625 = d624;
        f626 += f625;
        d626 = d625;
        f627 += f626;
        d627 = d626;
        f628 += f627;
        d628 = d627;
        f629 += f628;
        d629 = d628;
        f630 += f629;
        d630 = d629;
        f631 += f630;
        d631 = d630;
        f632 += f631;
        d632 = d631;
        f633 += f632;
        d633 = d632;
        f634 += f633;
        d634 = d633;
        f635 += f634;
        d635 = d634;
        f636 += f635;
        d636 = d635;
        f637 += f636;
        d637 = d636;
        f638 += f637;
        d638 = d637;
        f639 += f638;
        d639 = d638;
        f640 += f639;
        d640 = d639;
        f641 += f640;
        d641 = d640;
        f642 += f641;
        d642 = d641;
        f643 += f642;
        d643 = d642;
        f644 += f643;
        d644 = d643;
        f645 += f644;
        d645 = d644;
        f646 += f645;
        d646 = d645;
        f647 += f646;
        d647 = d646;
        f648 += f647;
        d648 = d647;
        f649 += f648;
        d649 = d648;
        f650 += f649;
        d650 = d649;
        f651 += f650;
        d651 = d650;
        f652 += f651;
        d652 = d651;
        f653 += f652;
        d653 = d652;
        f654 += f653;
        d654 = d653;
        f655 += f654;
        d655 = d654;
        f656 += f655;
        d656 = d655;
        f657 += f656;
        d657 = d656;
        f658 += f657;
        d658 = d657;
        f659 += f658;
        d659 = d658;
        f660 += f659;
        d660 = d659;
        f661 += f660;
        d661 = d660;
        f662 += f661;
        d662 = d661;
        f663 += f662;
        d663 = d662;
        f664 += f663;
        d664 = d663;
        f665 += f664;
        d665 = d664;
        f666 += f665;
        d666 = d665;
        f667 += f666;
        d667 = d666;
        f668 += f667;
        d668 = d667;
        f669 += f668;
        d669 = d668;
        f670 += f669;
        d670 = d669;
        f671 += f670;
        d671 = d670;
        f672 += f671;
        d672 = d671;
        f673 += f672;
        d673 = d672;
        f674 += f673;
        d674 = d673;
        f675 += f674;
        d675 = d674;
        f676 += f675;
        d676 = d675;
        f677 += f676;
        d677 = d676;
        f678 += f677;
        d678 = d677;
        f679 += f678;
        d679 = d678;
        f680 += f679;
        d680 = d679;
        f681 += f680;
        d681 = d680;
        f682 += f681;
        d682 = d681;
        f683 += f682;
        d683 = d682;
        f684 += f683;
        d684 = d683;
        f685 += f684;
        d685 = d684;
        f686 += f685;
        d686 = d685;
        f687 += f686;
        d687 = d686;
        f688 += f687;
        d688 = d687;
        f689 += f688;
        d689 = d688;
        f690 += f689;
        d690 = d689;
        f691 += f690;
        d691 = d690;
        f692 += f691;
        d692 = d691;
        f693 += f692;
        d693 = d692;
        f694 += f693;
        d694 = d693;
        f695 += f694;
        d695 = d694;
        f696 += f695;
        d696 = d695;
        f697 += f696;
        d697 = d696;
        f698 += f697;
        d698 = d697;
        f699 += f698;
        d699 = d698;
        f700 += f699;
        d700 = d699;
        f701 += f700;
        d701 = d700;
        f702 += f701;
        d702 = d701;
        f703 += f702;
        d703 = d702;
        f704 += f703;
        d704 = d703;
        f705 += f704;
        d705 = d704;
        f706 += f705;
        d706 = d705;
        f707 += f706;
        d707 = d706;
        f708 += f707;
        d708 = d707;
        f709 += f708;
        d709 = d708;
        f710 += f709;
        d710 = d709;
        f711 += f710;
        d711 = d710;
        f712 += f711;
        d712 = d711;
        f713 += f712;
        d713 = d712;
        f714 += f713;
        d714 = d713;
        f715 += f714;
        d715 = d714;
        f716 += f715;
        d716 = d715;
        f717 += f716;
        d717 = d716;
        f718 += f717;
        d718 = d717;
        f719 += f718;
        d719 = d718;
        f720 += f719;
        d720 = d719;
        f721 += f720;
        d721 = d720;
        f722 += f721;
        d722 = d721;
        f723 += f722;
        d723 = d722;
        f724 += f723;
        d724 = d723;
        f725 += f724;
        d725 = d724;
        f726 += f725;
        d726 = d725;
        f727 += f726;
        d727 = d726;
        f728 += f727;
        d728 = d727;
        f729 += f728;
        d729 = d728;
        f730 += f729;
        d730 = d729;
        f731 += f730;
        d731 = d730;
        f732 += f731;
        d732 = d731;
        f733 += f732;
        d733 = d732;
        f734 += f733;
        d734 = d733;
        f735 += f734;
        d735 = d734;
        f736 += f735;
        d736 = d735;
        f737 += f736;
        d737 = d736;
        f738 += f737;
        d738 = d737;
        f739 += f738;
        d739 = d738;
        f740 += f739;
        d740 = d739;
        f741 += f740;
        d741 = d740;
        f742 += f741;
        d742 = d741;
        f743 += f742;
        d743 = d742;
        f744 += f743;
        d744 = d743;
        f745 += f744;
        d745 = d744;
        f746 += f745;
        d746 = d745;
        f747 += f746;
        d747 = d746;
        f748 += f747;
        d748 = d747;
        f749 += f748;
        d749 = d748;
        f750 += f749;
        d750 = d749;
        f751 += f750;
        d751 = d750;
        f752 += f751;
        d752 = d751;
        f753 += f752;
        d753 = d752;
        f754 += f753;
        d754 = d753;
        f755 += f754;
        d755 = d754;
        f756 += f755;
        d756 = d755;
        f757 += f756;
        d757 = d756;
        f758 += f757;
        d758 = d757;
        f759 += f758;
        d759 = d758;
        f760 += f759;
        d760 = d759;
        f761 += f760;
        d761 = d760;
        f762 += f761;
        d762 = d761;
        f763 += f762;
        d763 = d762;
        f764 += f763;
        d764 = d763;
        f765 += f764;
        d765 = d764;
        f766 += f765;
        d766 = d765;
        f767 += f766;
        d767 = d766;
        f768 += f767;
        d768 = d767;
        f769 += f768;
        d769 = d768;
        f770 += f769;
        d770 = d769;
        f771 += f770;
        d771 = d770;
        f772 += f771;
        d772 = d771;
        f773 += f772;
        d773 = d772;
        f774 += f773;
        d774 = d773;
        f775 += f774;
        d775 = d774;
        f776 += f775;
        d776 = d775;
        f777 += f776;
        d777 = d776;
        f778 += f777;
        d778 = d777;
        f779 += f778;
        d779 = d778;
        f780 += f779;
        d780 = d779;
        f781 += f780;
        d781 = d780;
        f782 += f781;
        d782 = d781;
        f783 += f782;
        d783 = d782;
        f784 += f783;
        d784 = d783;
        f785 += f784;
        d785 = d784;
        f786 += f785;
        d786 = d785;
        f787 += f786;
        d787 = d786;
        f788 += f787;
        d788 = d787;
        f789 += f788;
        d789 = d788;
        f790 += f789;
        d790 = d789;
        f791 += f790;
        d791 = d790;
        f792 += f791;
        d792 = d791;
        f793 += f792;
        d793 = d792;
        f794 += f793;
        d794 = d793;
        f795 += f794;
        d795 = d794;
        f796 += f795;
        d796 = d795;
        f797 += f796;
        d797 = d796;
        f798 += f797;
        d798 = d797;
        f799 += f798;
        d799 = d798;
        f800 += f799;
        d800 = d799;
        f801 += f800;
        d801 = d800;
        f802 += f801;
        d802 = d801;
        f803 += f802;
        d803 = d802;
        f804 += f803;
        d804 = d803;
        f805 += f804;
        d805 = d804;
        f806 += f805;
        d806 = d805;
        f807 += f806;
        d807 = d806;
        f808 += f807;
        d808 = d807;
        f809 += f808;
        d809 = d808;
        f810 += f809;
        d810 = d809;
        f811 += f810;
        d811 = d810;
        f812 += f811;
        d812 = d811;
        f813 += f812;
        d813 = d812;
        f814 += f813;
        d814 = d813;
        f815 += f814;
        d815 = d814;
        f816 += f815;
        d816 = d815;
        f817 += f816;
        d817 = d816;
        f818 += f817;
        d818 = d817;
        f819 += f818;
        d819 = d818;
        f820 += f819;
        d820 = d819;
        f821 += f820;
        d821 = d820;
        f822 += f821;
        d822 = d821;
        f823 += f822;
        d823 = d822;
        f824 += f823;
        d824 = d823;
        f825 += f824;
        d825 = d824;
        f826 += f825;
        d826 = d825;
        f827 += f826;
        d827 = d826;
        f828 += f827;
        d828 = d827;
        f829 += f828;
        d829 = d828;
        f830 += f829;
        d830 = d829;
        f831 += f830;
        d831 = d830;
        f832 += f831;
        d832 = d831;
        f833 += f832;
        d833 = d832;
        f834 += f833;
        d834 = d833;
        f835 += f834;
        d835 = d834;
        f836 += f835;
        d836 = d835;
        f837 += f836;
        d837 = d836;
        f838 += f837;
        d838 = d837;
        f839 += f838;
        d839 = d838;
        f840 += f839;
        d840 = d839;
        f841 += f840;
        d841 = d840;
        f842 += f841;
        d842 = d841;
        f843 += f842;
        d843 = d842;
        f844 += f843;
        d844 = d843;
        f845 += f844;
        d845 = d844;
        f846 += f845;
        d846 = d845;
        f847 += f846;
        d847 = d846;
        f848 += f847;
        d848 = d847;
        f849 += f848;
        d849 = d848;
        f850 += f849;
        d850 = d849;
        f851 += f850;
        d851 = d850;
        f852 += f851;
        d852 = d851;
        f853 += f852;
        d853 = d852;
        f854 += f853;
        d854 = d853;
        f855 += f854;
        d855 = d854;
        f856 += f855;
        d856 = d855;
        f857 += f856;
        d857 = d856;
        f858 += f857;
        d858 = d857;
        f859 += f858;
        d859 = d858;
        f860 += f859;
        d860 = d859;
        f861 += f860;
        d861 = d860;
        f862 += f861;
        d862 = d861;
        f863 += f862;
        d863 = d862;
        f864 += f863;
        d864 = d863;
        f865 += f864;
        d865 = d864;
        f866 += f865;
        d866 = d865;
        f867 += f866;
        d867 = d866;
        f868 += f867;
        d868 = d867;
        f869 += f868;
        d869 = d868;
        f870 += f869;
        d870 = d869;
        f871 += f870;
        d871 = d870;
        f872 += f871;
        d872 = d871;
        f873 += f872;
        d873 = d872;
        f874 += f873;
        d874 = d873;
        f875 += f874;
        d875 = d874;
        f876 += f875;
        d876 = d875;
        f877 += f876;
        d877 = d876;
        f878 += f877;
        d878 = d877;
        f879 += f878;
        d879 = d878;
        f880 += f879;
        d880 = d879;
        f881 += f880;
        d881 = d880;
        f882 += f881;
        d882 = d881;
        f883 += f882;
        d883 = d882;
        f884 += f883;
        d884 = d883;
        f885 += f884;
        d885 = d884;
        f886 += f885;
        d886 = d885;
        f887 += f886;
        d887 = d886;
        f888 += f887;
        d888 = d887;
        f889 += f888;
        d889 = d888;
        f890 += f889;
        d890 = d889;
        f891 += f890;
        d891 = d890;
        f892 += f891;
        d892 = d891;
        f893 += f892;
        d893 = d892;
        f894 += f893;
        d894 = d893;
        f895 += f894;
        d895 = d894;
        f896 += f895;
        d896 = d895;
        f897 += f896;
        d897 = d896;
        f898 += f897;
        d898 = d897;
        f899 += f898;
        d899 = d898;
        f900 += f899;
        d900 = d899;
        f901 += f900;
        d901 = d900;
        f902 += f901;
        d902 = d901;
        f903 += f902;
        d903 = d902;
        f904 += f903;
        d904 = d903;
        f905 += f904;
        d905 = d904;
        f906 += f905;
        d906 = d905;
        f907 += f906;
        d907 = d906;
        f908 += f907;
        d908 = d907;
        f909 += f908;
        d909 = d908;
        f910 += f909;
        d910 = d909;
        f911 += f910;
        d911 = d910;
        f912 += f911;
        d912 = d911;
        f913 += f912;
        d913 = d912;
        f914 += f913;
        d914 = d913;
        f915 += f914;
        d915 = d914;
        f916 += f915;
        d916 = d915;
        f917 += f916;
        d917 = d916;
        f918 += f917;
        d918 = d917;
        f919 += f918;
        d919 = d918;
        f920 += f919;
        d920 = d919;
        f921 += f920;
        d921 = d920;
        f922 += f921;
        d922 = d921;
        f923 += f922;
        d923 = d922;
        f924 += f923;
        d924 = d923;
        f925 += f924;
        d925 = d924;
        f926 += f925;
        d926 = d925;
        f927 += f926;
        d927 = d926;
        f928 += f927;
        d928 = d927;
        f929 += f928;
        d929 = d928;
        f930 += f929;
        d930 = d929;
        f931 += f930;
        d931 = d930;
        f932 += f931;
        d932 = d931;
        f933 += f932;
        d933 = d932;
        f934 += f933;
        d934 = d933;
        f935 += f934;
        d935 = d934;
        f936 += f935;
        d936 = d935;
        f937 += f936;
        d937 = d936;
        f938 += f937;
        d938 = d937;
        f939 += f938;
        d939 = d938;
        f940 += f939;
        d940 = d939;
        f941 += f940;
        d941 = d940;
        f942 += f941;
        d942 = d941;
        f943 += f942;
        d943 = d942;
        f944 += f943;
        d944 = d943;
        f945 += f944;
        d945 = d944;
        f946 += f945;
        d946 = d945;
        f947 += f946;
        d947 = d946;
        f948 += f947;
        d948 = d947;
        f949 += f948;
        d949 = d948;
        f950 += f949;
        d950 = d949;
        f951 += f950;
        d951 = d950;
        f952 += f951;
        d952 = d951;
        f953 += f952;
        d953 = d952;
        f954 += f953;
        d954 = d953;
        f955 += f954;
        d955 = d954;
        f956 += f955;
        d956 = d955;
        f957 += f956;
        d957 = d956;
        f958 += f957;
        d958 = d957;
        f959 += f958;
        d959 = d958;
        f960 += f959;
        d960 = d959;
        f961 += f960;
        d961 = d960;
        f962 += f961;
        d962 = d961;
        f963 += f962;
        d963 = d962;
        f964 += f963;
        d964 = d963;
        f965 += f964;
        d965 = d964;
        f966 += f965;
        d966 = d965;
        f967 += f966;
        d967 = d966;
        f968 += f967;
        d968 = d967;
        f969 += f968;
        d969 = d968;
        f970 += f969;
        d970 = d969;
        f971 += f970;
        d971 = d970;
        f972 += f971;
        d972 = d971;
        f973 += f972;
        d973 = d972;
        f974 += f973;
        d974 = d973;
        f975 += f974;
        d975 = d974;
        f976 += f975;
        d976 = d975;
        f977 += f976;
        d977 = d976;
        f978 += f977;
        d978 = d977;
        f979 += f978;
        d979 = d978;
        f980 += f979;
        d980 = d979;
        f981 += f980;
        d981 = d980;
        f982 += f981;
        d982 = d981;
        f983 += f982;
        d983 = d982;
        f984 += f983;
        d984 = d983;
        f985 += f984;
        d985 = d984;
        f986 += f985;
        d986 = d985;
        f987 += f986;
        d987 = d986;
        f988 += f987;
        d988 = d987;
        f989 += f988;
        d989 = d988;
        f990 += f989;
        d990 = d989;
        f991 += f990;
        d991 = d990;
        f992 += f991;
        d992 = d991;
        f993 += f992;
        d993 = d992;
        f994 += f993;
        d994 = d993;
        f995 += f994;
        d995 = d994;
        f996 += f995;
        d996 = d995;
        f997 += f996;
        d997 = d996;
        f998 += f997;
        d998 = d997;
        f999 += f998;
        d999 = d998;
        return f999 + d999;
    }

    static void largeFrameTest() {
        long res = largeFrame();
        if (res == 499500) {
            System.out.println("largeFrame passes");
        } else {
            System.out.println("largeFrame fails: expected 49950, got " + res);
        }
    }

    static void largeFrameTestFloat() {
        double res = largeFrameFloat();
        if (res == 499500.0) {
            System.out.println("largeFrameFloat passes");
        } else {
            System.out.println("largeFrameFloat fails: expected 49950, got " + res);
        }
    }
}

class SpinThread extends Thread {
    int mPriority;

    SpinThread(int prio) {
        super("Spin prio=" + prio);
        mPriority = prio;
    }

    public void run() {
        setPriority(mPriority);
        while (true) {}
    }
}

class Foo {
    private int bar = 1234;
    private long lbar = 1234;

    public static Foo getNullFoo() {
      // Make this a bit complicated so that it's not inlined.
      Foo foo = new Foo();
      return (barBar(foo) != 0) ? null : foo;
    }

    // Looks similar to a direct method, make sure we're null checking
    static int barBar(Foo foo) {
        return foo.bar;
    }

    public int iConst0x1234() {
        return 0x1234;
    }

    public long iConst0x123443211234() {
        return 0x123443211234L;
    }

    public void setBar1(int a1) {
        bar = a1;
    }
    public void setBar2(int a1, int a2) {
        bar = a2;
    }
    public void setBar3(int a1, int a2, int a3) {
        bar = a3;
    }
    public void setBar4(int a1, int a2, int a3, int a4) {
        bar = a4;
    }
    public void setBar5(int a1, int a2, int a3, int a4, int a5) {
        bar = a5;
    }
    public int getBar0() {
        return bar;
    }
    public int getBar1(int a1) {
        return bar;
    }
    public int getBar2(int a1, int a2) {
        return bar;
    }
    public int getBar3(int a1, int a2, int a3) {
        return bar;
    }
    public int getBar4(int a1, int a2, int a3, int a4) {
        return bar;
    }
    public int getBar5(int a1, int a2, int a3, int a4, int a5) {
        return bar;
    }

    public int ident0(int a1) {
        return a1;
    }

    public int ident1(int a2, int a1) {
        return a1;
    }

    public int ident2(int a3, int a2, int a1) {
        return a1;
    }

    public int ident3(int a4, int a3, int a2, int a1) {
        return a1;
    }

    public int ident4(int a5, int a4, int a3, int a2, int a1) {
        return a1;
    }

    public int ident5(int a6, int a5, int a4, int a3, int a2, int a1) {
        return a1;
    }


    public void wideSetBar1(long a1) {
        lbar = a1;
    }
    public void wideSetBar2(long a1, long a2) {
        lbar = a2;
    }
    public void wideSetBar3(long a1, long a2, long a3) {
        lbar = a3;
    }
    public void wideSetBar4(long a1, long a2, long a3, long a4) {
        lbar = a4;
    }
    public void wideSetBar5(long a1, long a2, long a3, long a4, long a5) {
        lbar = a5;
    }
    public void wideSetBar2i(int a1, long a2) {
      lbar = a2;
    }
    public void wideSetBar3i(int a1, int a2, long a3) {
        lbar = a3;
    }
    public void wideSetBar4i(int a1, int a2, int a3, long a4) {
        lbar = a4;
    }
    public void wideSetBar5i(int a1, int a2, int a3, int a4, long a5) {
        lbar = a5;
    }
    public long wideGetBar0() {
        return lbar;
    }
    public long wideGetBar1(long a1) {
        return lbar;
    }
    public long wideGetBar2(long a1, long a2) {
        return lbar;
    }
    public long wideGetBar3(long a1, long a2, long a3) {
        return lbar;
    }
    public long wideGetBar4(long a1, long a2, long a3, long a4) {
        return lbar;
    }
    public long wideGetBar5(long a1, long a2, long a3, long a4, long a5) {
        return lbar;
    }

    public long wideIdent0(long a1) {
        return a1;
    }

    public long wideIdent1(int a2, long a1) {
        return a1;
    }

    public long wideIdent2(int a3, int a2, long a1) {
        return a1;
    }

    public long wideIdent3(int a4, int a3, int a2, long a1) {
        return a1;
    }

    public long wideIdent4(int a5, int a4, int a3, int a2, long a1) {
        return a1;
    }

    public long wideIdent5(int a6, int a5, int a4, int a3, int a2, long a1) {
        return a1;
    }
    public Foo setBar1ReturnThis(int a1) {
        bar = a1;
        return this;
    }
    public Foo setBar2ReturnThis(int a1, int a2) {
        bar = a2;
        return this;
    }
    public Foo setBar3ReturnThis(int a1, int a2, int a3) {
        bar = a3;
        return this;
    }
    public Foo setBar4ReturnThis(int a1, int a2, int a3, int a4) {
        bar = a4;
        return this;
    }
    public Foo setBar5ReturnThis(int a1, int a2, int a3, int a4, int a5) {
        bar = a5;
        return this;
    }
    public Foo wideSetBar1ReturnThis(long a1) {
        lbar = a1;
        return this;
    }
    public Foo wideSetBar2ReturnThis(long a1, long a2) {
        lbar = a2;
        return this;
    }
    public Foo wideSetBar3ReturnThis(long a1, long a2, long a3) {
        lbar = a3;
        return this;
    }
    public Foo wideSetBar4ReturnThis(long a1, long a2, long a3, long a4) {
        lbar = a4;
        return this;
    }
    public Foo wideSetBar5ReturnThis(long a1, long a2, long a3, long a4, long a5) {
        lbar = a5;
        return this;
    }
    public Foo wideSetBar2iReturnThis(int a1, long a2) {
        lbar = a2;
        return this;
    }
    public Foo wideSetBar3iReturnThis(int a1, int a2, long a3) {
        lbar = a3;
        return this;
    }
    public Foo wideSetBar4iReturnThis(int a1, int a2, int a3, long a4) {
        lbar = a4;
        return this;
    }
    public Foo wideSetBar5iReturnThis(int a1, int a2, int a3, int a4, long a5) {
        lbar = a5;
        return this;
    }
    public int setBar1ReturnBarArg(int a1) {
        bar = a1;
        return a1;
    }
    public int setBar2ReturnBarArg(int a1, int a2) {
        bar = a2;
        return a2;
    }
    public int setBar3ReturnBarArg(int a1, int a2, int a3) {
        bar = a3;
        return a3;
    }
    public int setBar4ReturnBarArg(int a1, int a2, int a3, int a4) {
        bar = a4;
        return a4;
    }
    public int setBar5ReturnBarArg(int a1, int a2, int a3, int a4, int a5) {
        bar = a5;
        return a5;
    }
    public long wideSetBar1ReturnBarArg(long a1) {
        lbar = a1;
        return a1;
    }
    public long wideSetBar2ReturnBarArg(long a1, long a2) {
        lbar = a2;
        return a2;
    }
    public long wideSetBar3ReturnBarArg(long a1, long a2, long a3) {
        lbar = a3;
        return a3;
    }
    public long wideSetBar4ReturnBarArg(long a1, long a2, long a3, long a4) {
        lbar = a4;
        return a4;
    }
    public long wideSetBar5ReturnBarArg(long a1, long a2, long a3, long a4, long a5) {
        lbar = a5;
        return a5;
    }
    public long wideSetBar2iReturnBarArg(int a1, long a2) {
        lbar = a2;
        return a2;
    }
    public long wideSetBar3iReturnBarArg(int a1, int a2, long a3) {
        lbar = a3;
        return a3;
    }
    public long wideSetBar4iReturnBarArg(int a1, int a2, int a3, long a4) {
        lbar = a4;
        return a4;
    }
    public long wideSetBar5iReturnBarArg(int a1, int a2, int a3, int a4, long a5) {
        lbar = a5;
        return a5;
    }
    public int setBar2ReturnDummyArg1(int a1, int a2) {
        bar = a2;
        return a1;
    }
    public int setBar3ReturnDummyArg2(int a1, int a2, int a3) {
        bar = a3;
        return a2;
    }
    public int setBar4ReturnDummyArg3(int a1, int a2, int a3, int a4) {
        bar = a4;
        return a3;
    }
    public int setBar5ReturnDummyArg4(int a1, int a2, int a3, int a4, int a5) {
        bar = a5;
        return a4;
    }
    public long wideSetBar2ReturnDummyArg1(long a1, long a2) {
        lbar = a2;
        return a1;
    }
    public long wideSetBar3ReturnDummyArg2(long a1, long a2, long a3) {
        lbar = a3;
        return a2;
    }
    public long wideSetBar4ReturnDummyArg3(long a1, long a2, long a3, long a4) {
        lbar = a4;
        return a3;
    }
    public long wideSetBar5ReturnDummyArg4(long a1, long a2, long a3, long a4, long a5) {
        lbar = a5;
        return a4;
    }
    public int wideSetBar2iReturnDummyArg1(int a1, long a2) {
        lbar = a2;
        return a1;
    }
    public int wideSetBar3iReturnDummyArg2(int a1, int a2, long a3) {
        lbar = a3;
        return a2;
    }
    public int wideSetBar4iReturnDummyArg3(int a1, int a2, int a3, long a4) {
        lbar = a4;
        return a3;
    }
    public int wideSetBar5iReturnDummyArg4(int a1, int a2, int a3, int a4, long a5) {
        lbar = a5;
        return a4;
    }
}

class LVNTests {
    private LVNTests link = null;
    private int value = 0;

    private void setLink(LVNTests l) {
        link = l;
    }

    private static void causeNPE1(LVNTests lhs, LVNTests rhs) {
        LVNTests link1 = lhs.link;
        rhs.link = null;
        LVNTests link2 = lhs.link;
        int value1 = link1.value;
        int value2 = link2.value;
        System.out.println("LVNTests.testNPE1 fails with " + value1 + " and " + value2);
    }

    public static void testNPE1() {
        LVNTests t = new LVNTests();
        t.link = new LVNTests();
        try {
          causeNPE1(t, t);
        } catch (NullPointerException e) {
          System.out.println("LVNTests.testNPE1 passes");
        }
    }

    private static void causeNPE2(LVNTests lhs, LVNTests rhs) {
      LVNTests link1 = lhs.link;
      rhs.setLink(null);
      LVNTests link2 = lhs.link;
      int value1 = link1.value;
      int value2 = link2.value;
      System.out.println("LVNTests.testNPE2 fails with " + value1 + " and " + value2);
    }

    public static void testNPE2() {
        LVNTests t = new LVNTests();
        t.link = new LVNTests();
        try {
          causeNPE2(t, t);
        } catch (NullPointerException e) {
          System.out.println("LVNTests.testNPE2 passes");
        }
    }
}

class MirOpSelectTests {
    private static int ifEqzThen0Else1(int i) { return (i == 0) ? 0 : 1; }
    private static int ifEqzThen0Else8(int i) { return (i == 0) ? 0 : 8; }
    private static int ifEqzThen1Else5(int i) { return (i == 0) ? 1 : 5; }
    private static int ifEqzThenMinus1Else3(int i) { return (i == 0) ? -1 : 3; }
    private static int ifEqzThen11Else23(int i) { return (i == 0) ? 11 : 23; }
    private static int ifEqzThen54321Else87654321(int i) { return (i == 0) ? 54321 : 87654321; }
    private static int ifNezThen0Else1(int i) { return (i != 0) ? 0 : 1; }
    private static int ifNezThen0Else8(int i) { return (i != 0) ? 0 : 8; }
    private static int ifNezThen1Else5(int i) { return (i != 0) ? 1 : 5; }
    private static int ifNezThenMinus1Else3(int i) { return (i != 0) ? -1 : 3; }
    private static int ifNezThen11Else23(int i) { return (i != 0) ? 11 : 23; }
    private static int ifNezThen54321Else87654321(int i) { return (i != 0) ? 54321 : 87654321; }
    private static int ifLtzThen3Else5(int i) { return (i < 0) ? 3 : 5; }
    private static int ifGezThen7Else4(int i) { return (i >= 0) ? 7 : 4; }
    private static int ifGtzThen2Else9(int i) { return (i > 0) ? 2 : 9; }
    private static int ifLezThen8Else0(int i) { return (i <= 0) ? 8 : 0; }
    private static int ifGtzThen8Else9(int i) { return (i > 0) ? 8 : 9; }

    private static int ifEqz(int src, int thn, int els) { return (src == 0) ? thn : els; }
    private static int ifNez(int src, int thn, int els) { return (src != 0) ? thn : els; }
    private static int ifLtz(int src, int thn, int els) { return (src < 0) ? thn : els; }
    private static int ifGez(int src, int thn, int els) { return (src >= 0) ? thn : els; }
    private static int ifGtz(int src, int thn, int els) { return (src > 0) ? thn : els; }
    private static int ifLez(int src, int thn, int els) { return (src <= 0) ? thn : els; }

    public static void testIfCcz() {
        int[] results = new int[] {
            ifEqzThen0Else1(-1), 1,
            ifEqzThen0Else1(0), 0,
            ifEqzThen0Else1(1), 1,
            ifEqzThen0Else8(-1), 8,
            ifEqzThen0Else8(0), 0,
            ifEqzThen0Else8(1), 8,
            ifEqzThen1Else5(-1), 5,
            ifEqzThen1Else5(0), 1,
            ifEqzThen1Else5(1), 5,
            ifEqzThenMinus1Else3(-1), 3,
            ifEqzThenMinus1Else3(0), -1,
            ifEqzThenMinus1Else3(1), 3,
            ifEqzThen11Else23(-1), 23,
            ifEqzThen11Else23(0), 11,
            ifEqzThen11Else23(1), 23,
            ifEqzThen54321Else87654321(-1), 87654321,
            ifEqzThen54321Else87654321(0), 54321,
            ifEqzThen54321Else87654321(1), 87654321,
            ifNezThen0Else1(-1), 0,
            ifNezThen0Else1(0), 1,
            ifNezThen0Else1(1), 0,
            ifNezThen0Else8(-1), 0,
            ifNezThen0Else8(0), 8,
            ifNezThen0Else8(1), 0,
            ifNezThen1Else5(-1), 1,
            ifNezThen1Else5(0), 5,
            ifNezThen1Else5(1), 1,
            ifNezThenMinus1Else3(-1), -1,
            ifNezThenMinus1Else3(0), 3,
            ifNezThenMinus1Else3(1), -1,
            ifNezThen11Else23(-1), 11,
            ifNezThen11Else23(0), 23,
            ifNezThen11Else23(1), 11,
            ifNezThen54321Else87654321(-1), 54321,
            ifNezThen54321Else87654321(0), 87654321,
            ifNezThen54321Else87654321(1), 54321,
            ifLtzThen3Else5(-1), 3,
            ifLtzThen3Else5(0), 5,
            ifLtzThen3Else5(1), 5,
            ifGezThen7Else4(-1), 4,
            ifGezThen7Else4(0), 7,
            ifGezThen7Else4(1), 7,
            ifGtzThen2Else9(-1), 9,
            ifGtzThen2Else9(0), 9,
            ifGtzThen2Else9(1), 2,
            ifLezThen8Else0(-1), 8,
            ifLezThen8Else0(0), 8,
            ifLezThen8Else0(1), 0,
            ifEqz(-1, 101, 201), 201,
            ifEqz(0, 102, 202), 102,
            ifEqz(1, 103, 203), 203,
            ifNez(-1, 104, 204), 104,
            ifNez(0, 105, 205), 205,
            ifNez(1, 106, 206), 106,
            ifLtz(-1, 107, 207), 107,
            ifLtz(0, 108, 208), 208,
            ifLtz(1, 109, 209), 209,
            ifGez(-1, 110, 210), 210,
            ifGez(0, 111, 211), 111,
            ifGez(1, 112, 212), 112,
            ifGtz(-1, 113, 213), 213,
            ifGtz(0, 114, 214), 214,
            ifGtz(1, 115, 215), 115,
            ifLez(-1, 116, 216), 116,
            ifLez(0, 117, 217), 117,
            ifLez(1, 118, 218), 218,
            ifGtzThen8Else9(0), 9,
            ifGtzThen8Else9(1), 8
        };

        boolean success = true;
        StringBuilder fails = new StringBuilder();
        for (int i = 0; i != results.length; i += 2) {
            if (results[i] != results[i + 1]) {
                success = false;
                fails.append("\n  #" + (i / 2) + ": " + results[i] + " != " + results[i + 1]);
            }
        }
        if (success) {
            System.out.println("testIfCcz passes");
        } else {
            System.out.println("testIfCcz fails for" + fails.toString());
        }
    }
}

class LiveFlags {
  private static void show_results(double a[], double b[], int trip) {
    if ((a[0]+a[1]+b[0]+b[1]) == 0) {
      System.out.println("LiveFlags passes trip " + trip);
    } else {
      System.out.println("LiveFlags fails trip " + trip);
      System.out.println("a[0] = " + a[0] + " a[1] = " + a[1]);
      System.out.println("b[0] = " + b[0] + " b[1] = " + b[1]);
    }
  }
  static void test()
  {
    final double A[] = new double[2];
    final double B[] = new double[2];
    final double C[] = new double[2];
    B[0] = B[1] = 0.0;
    A[0] = A[1] = 0.0;
    C[0] = C[1] = 0.0;
    for (int i = 3; i >= 1; i--) {
      if ( (i & 1) == 0) {
        continue;
      }
      if ( (i & 2) != 0 ) {
        B[1] = -B[1];
      }
      show_results(A, B, i);
      A[0] = C[0]; A[1] = C[1];
    }
  }
}

class B16177324Values {
  public static int values[] = { 42 };
}

class B16177324ValuesKiller {
  public static int values[] = { 1234 };
  static {
    B16177324Values.values = null;
  }
}
