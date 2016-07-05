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
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static org.mockito.Mockito.*;

public class ScalaSqlInjectionSlickDetectorTest extends BaseDetectorTest {

    /**
     * Test the API coverage for SqlInjectionDetector (loadConfiguredSinks("sql-scala-slick.txt", "SCALA_SQL_INJECTION_SLICK);)
     * @throws Exception
     */
    @Test
    public void detectSqlInjection() throws Exception {
        //FindSecBugsGlobalConfig.getInstance().setDebugPrintInstructionVisited(true);
        //FindSecBugsGlobalConfig.getInstance().setDebugPrintInvocationVisited(false);
        //FindSecBugsGlobalConfig.getInstance().setDebugTaintState(true);

        //Locate test code
        String[] files = {
                getClassFilePath("bytecode_samples/scala_sql_injection.jar")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Assertions for bugs
        Map<String, int[]> methodBugLines = new HashMap<String, int[]>();
        methodBugLines.put("vulnerableSlick1", new int[]{180});
        methodBugLines.put("vulnerableSlick2", new int[]{201});

        for (Entry<String, int[]> entry : methodBugLines.entrySet()) {

            // Lets check every line specified above
            for (int line : entry.getValue()) {
                verify(reporter).doReportBug(
                        bugDefinition()
                                .bugType("SCALA_SQL_INJECTION_SLICK")
                                .inClass("SqlController").inMethod(entry.getKey()).atLine(line)
                                .build()
                );
            }
        }


        //Assertions for safe calls and false positives
        Map<String, int[]> methodFalsePositiveLines = new HashMap<String, int[]>();
        methodFalsePositiveLines.put("variousSafeSlick1", new int[]{190, 191});
        methodFalsePositiveLines.put("variousSafeSlick2", new int[]{211, 212});

        for (Entry<String, int[]> entry : methodFalsePositiveLines.entrySet()) {

            // Lets check every line specified above
            for (int line : entry.getValue()) {
                verify(reporter,never()).doReportBug(
                        bugDefinition()
                                .bugType("SCALA_SQL_INJECTION_SLICK")
                                .inClass("SqlController").inMethod(entry.getKey()).atLine(line)
                                .build()
                );
            }
        }
    }
}
