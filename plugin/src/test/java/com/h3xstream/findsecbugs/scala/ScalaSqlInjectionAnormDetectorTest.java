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
import java.util.List;

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

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm1").atLine(25)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm2").atLine(32)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm3").atLine(39)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm4").atLine(46)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm5").atLine(53)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm6").atLine(60)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm7").atLine(67)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm8").atLine(74)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm9").atLine(81)
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SCALA_SQL_INJECTION_ANORM")
                        .inClass("SqlController").inMethod("vulnerableAnorm10").atLine(88)
                        .build()
        );



        List<Integer> linesSelectFalsePositives = Arrays.asList(95, 96, 97, /**/ 99, 100, 101);
        for(int line : linesSelectFalsePositives) {
            verify(reporter,never()).doReportBug(
                    bugDefinition()
                            .bugType("SCALA_SQL_INJECTION_ANORM")
                            .inClass("SqlController").inMethod("variousSafeSelect").atLine(line)
                            .build()
            );
        }

        List<Integer> linesUpdateFalsePositives = Arrays.asList(109, 110, 111, /**/ 113, 114, 115);
        for(int line : linesUpdateFalsePositives) {
            verify(reporter,never()).doReportBug(
                    bugDefinition()
                            .bugType("SCALA_SQL_INJECTION_ANORM")
                            .inClass("SqlController").inMethod("variousSafeUpdate").atLine(line)
                            .build()
            );
        }

        List<Integer> linesInsertFalsePositives = Arrays.asList(123, 124, 125);
        for(int line : linesInsertFalsePositives) {
            verify(reporter,never()).doReportBug(
                    bugDefinition()
                            .bugType("SCALA_SQL_INJECTION_ANORM")
                            .inClass("SqlController").inMethod("variousSafeInsert").atLine(line)
                            .build()
            );
        }
    }
}
