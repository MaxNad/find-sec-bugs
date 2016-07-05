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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static org.mockito.Mockito.*;

public class ScalaSqlInjectionAnormDetectorTest extends BaseDetectorTest {

    /**
     * Test the API coverage for SqlInjectionDetector (loadConfiguredSinks("sql-scala-anorm.txt", "SCALA_SQL_INJECTION_ANORM);)
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
        //methodBugLines.put("vulnerableAnorm1", new int[]{25});
        //methodBugLines.put("vulnerableAnorm2", new int[]{32, 33});
        //methodBugLines.put("vulnerableAnorm3", new int[]{41});
        //methodBugLines.put("vulnerableAnorm4", new int[]{48, 49});
        //methodBugLines.put("vulnerableAnorm5", new int[]{57});
        //methodBugLines.put("vulnerableAnorm6", new int[]{64, 65});
        //methodBugLines.put("vulnerableAnorm7", new int[]{73});
        //methodBugLines.put("vulnerableAnorm8", new int[]{80, 81});
        //methodBugLines.put("vulnerableAnorm9", new int[]{89});
        //methodBugLines.put("vulnerableAnorm10", new int[]{96, 97});
        //methodBugLines.put("vulnerableAnorm11", new int[]{105, 106, 107, /**/ 109, 110, 111});

        for (Entry<String, int[]> entry : methodBugLines.entrySet()) {

            // Lets check every line specified above
            for (int line : entry.getValue()) {
                verify(reporter).doReportBug(
                        bugDefinition()
                                .bugType("SCALA_SQL_INJECTION_ANORM")
                                .inClass("SqlController").inMethod(entry.getKey()).atLine(line)
                                .build()
                );
            }
        }


        //Assertions for safe calls and false positives
        Map<String, int[]> methodFalsePositiveLines = new HashMap<String, int[]>();
        methodFalsePositiveLines.put("variousSafeAnormSelect", new int[]{119, 120, 121, 122, /**/ 124, 125, 126, 127});
        methodFalsePositiveLines.put("variousSafeAnormUpdate", new int[]{135, 136, 137, 138, /**/ 140, 141, 142, 143});
        methodFalsePositiveLines.put("variousSafeAnormInsert", new int[]{151, 152, 153, 154});
        methodFalsePositiveLines.put("variousSafeAnormBatch", new int[]{162, 163, 164, 165, 166});

        for (Entry<String, int[]> entry : methodFalsePositiveLines.entrySet()) {

            // Lets check every line specified above
            for (int line : entry.getValue()) {
                verify(reporter,never()).doReportBug(
                        bugDefinition()
                                .bugType("SCALA_SQL_INJECTION_ANORM")
                                .inClass("SqlController").inMethod(entry.getKey()).atLine(line)
                                .build()
                );
            }
        }
    }
}
