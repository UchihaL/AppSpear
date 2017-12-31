/*
 * Copyright (C) 2008 The Android Open Source Project
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

/**
 * Dalvik instruction exerciser.
 */
public class Main {
    /*
     * Start up.
     */
    public static void main(String[] args) {
        Main main = new Main();
        main.run();

        /* run through the heap to see if we trashed something */
        Runtime.getRuntime().gc();

        System.out.println("Done!");
    }

    public void run() {
        InstField instField = new InstField();
        instField.run();

        StaticField.run();

        IntMath.run();
        FloatMath.run();
        Compare.run();

        Monitor.run();
        Switch.run();
        Array.run();
        Classes.run();
        Goto.run();
        MethodCall.run();
        Throw.run();

        try {
            UnresTest1.run();
        } catch (VerifyError ve) {
            System.out.println("Caught: " + ve);
        }
        try {
            UnresTest1.run();
        } catch (VerifyError ve) {
            System.out.println("Caught (retry): " + ve);
        }

        try {
            UnresTest2.run();
        } catch (VerifyError ve) {
            System.out.println("Caught: " + ve);
        } catch (Throwable th) {
            // We and the RI throw ClassNotFoundException, but that isn't declared so javac
            // won't let us try to catch it.
            th.printStackTrace();
        }
        InternedString.run();
        GenSelect.run();
    }

    public static void assertTrue(boolean condition) {
        if (!condition) {
            throw new Error();
        }
    }
}
