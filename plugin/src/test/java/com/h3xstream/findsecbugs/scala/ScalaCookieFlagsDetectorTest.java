/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.scala;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class ScalaCookieFlagsDetectorTest extends BaseDetectorTest {

    @Test
    public void detectCookieFlags() throws Exception {
        //FindSecBugsGlobalConfig.getInstance().setDebugPrintInstructionVisited(true);
        //FindSecBugsGlobalConfig.getInstance().setDebugPrintInvocationVisited(false);
        //FindSecBugsGlobalConfig.getInstance().setDebugTaintState(true);

        //Locate test code
        String[] files = {
                getClassFilePath("bytecode_samples/scala_cookies.jar")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // Detect the Secure flag
        // Assertions for bugs
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("insecureCookie").atLine(8)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleInsecureCookies").atLine(13)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleInsecureCookies").atLine(14)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleSecureCookies").atLine(20)
                        .build()
        );

        // Assertions for safe calls and false positives
        // This method checks for a specific line because there is two cookies, one safe, one insecure
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleSecureCookies").atLine(21)
                        .build()
        );

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("safeSecureCookie")
                        .build()
        );

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_INSECURE_COOKIE")
                        .inClass("CookieFlagsController").inMethod("safeHttpOnlyCookie")
                        .build()
        );


        // Detect the HttpOnly flag
        // Assertions for bugs
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("nonHttpOnlyCookie").atLine(32)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleNonHttpOnlyCookie").atLine(37)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleNonHttpOnlyCookie").atLine(38)
                        .build()
        );

        // Assertions for safe calls and false positives
        // This method checks for a specific line because there is two cookies, one safe, one insecure
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("multipleHttpOnlyCookie").atLine(45)
                        .build()
        );

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("safeHttpOnlyCookie")
                        .build()
        );

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SCALA_HTTPONLY_COOKIE")
                        .inClass("CookieFlagsController").inMethod("safeSecureCookie")
                        .build()
        );
    }
}