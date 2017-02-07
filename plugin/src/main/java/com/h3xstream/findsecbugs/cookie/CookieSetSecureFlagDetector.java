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
package com.h3xstream.findsecbugs.cookie;

import com.h3xstream.findsecbugs.common.detectors.AbstractCallFlowDetector;
import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrameAdditionalVisitor;
import com.h3xstream.findsecbugs.taintanalysis.TaintLocation;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.ba.ClassContext;
import java.util.Iterator;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.LoadInstruction;
import org.apache.bcel.generic.MethodGen;
import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class CookieSetSecureFlagDetector extends AbstractCallFlowDetector implements TaintFrameAdditionalVisitor {

    private static final int TRUE_INT_VALUE = 1;

    private static final String INSECURE_COOKIE_TYPE = "INSECURE_COOKIE";

    private static final String COOKIE_OBJECT_TYPE = "javax/servlet/http/Cookie";

    private static final InvokeMatcherBuilder SET_SECURE_METHOD = invokeInstruction() //
            .atClass("javax/servlet/http/Cookie").atMethod("setSecure").withArgs("(Z)V");

    public CookieSetSecureFlagDetector(BugReporter bugReporter) {
        super(bugReporter);
        registerVisitor(this);
    }

    @Override
    protected void analyzeReturn(ClassContext classContext, Method method, InstructionHandle handle,
                                 ConstantPoolGen cpg, TaintFrame fact, String currentMethod) {
        for (int taintIndex = 0; taintIndex < fact.getNumSlots(); taintIndex++) {
            try {

                if (COOKIE_OBJECT_TYPE.equals(fact.getValue(taintIndex).getRealInstanceClassName())
                        && !fact.getValue(taintIndex).hasTag(Taint.Tag.HTTP_ONLY_COOKIE)
                        && fact.getValue(taintIndex).getLocations().size() > 0) {

                    Iterator<TaintLocation> iterator = fact.getValue(taintIndex).getLocations().iterator();
                    TaintLocation objectInitLocation = iterator.next();

                    while (iterator.hasNext()) {
                        TaintLocation taintLocation = iterator.next();
                        if (objectInitLocation.getPosition() > taintLocation.getPosition()) {
                            objectInitLocation = taintLocation;
                        }
                    }

                    BugInstance inst = new BugInstance(this, INSECURE_COOKIE_TYPE, Priorities.NORMAL_PRIORITY) //
                            .addClassAndMethod(objectInitLocation.getMethodDescriptor())
                            .addSourceLine(SourceLineAnnotation.fromVisitedInstruction(
                                    objectInitLocation.getMethodDescriptor(), objectInitLocation.getPosition()));
                    bugReporter.reportBug(inst);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void visitInvoke(InvokeInstruction instruction, ConstantPoolGen cpg, MethodGen methodGen, TaintFrame frameType) {
        //ByteCode.printOpCode(instruction, cpg);
        try {
            if (SET_SECURE_METHOD.matches(instruction, cpg) && frameType.getStackValue(0).getIntegerConstantValue().intValue() == TRUE_INT_VALUE) {
                frameType.getStackValue(1).addTag(Taint.Tag.HTTP_ONLY_COOKIE);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void visitLoad(LoadInstruction instruction, ConstantPoolGen cpg, MethodGen methodGen, TaintFrame frameType, int numProduced) { }
}