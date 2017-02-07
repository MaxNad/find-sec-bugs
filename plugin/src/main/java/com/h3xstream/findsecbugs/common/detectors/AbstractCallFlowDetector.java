package com.h3xstream.findsecbugs.common.detectors;

import com.h3xstream.findsecbugs.injection.AbstractInjectionDetector;
import com.h3xstream.findsecbugs.injection.InjectionPoint;
import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import java.util.Iterator;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.ReturnInstruction;

public abstract class AbstractCallFlowDetector  extends AbstractInjectionDetector {

    protected AbstractCallFlowDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    protected void analyzeMethod(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        TaintDataflow dataflow = getTaintDataFlow(classContext, method);
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        String currentMethod = getFullMethodName(classContext.getMethodGen(method));
        for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext();) {
            Location location = i.next();
            InstructionHandle handle = location.getHandle();
            Instruction instruction = handle.getInstruction();

            if (instruction instanceof ReturnInstruction) {
                TaintFrame fact = dataflow.getFactAtLocation(location);
                assert fact != null;
                if (!fact.isValid()) {
                    continue;
                }
                analyzeReturn(classContext, method, handle, cpg, fact, currentMethod);
            }
        }
    }

    @Override
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset) throws DataflowAnalysisException {
        return Priorities.IGNORE_PRIORITY;
    }

    @Override
    protected InjectionPoint getInjectionPoint(InvokeInstruction invoke, ConstantPoolGen cpg,
                                               InstructionHandle handle) {
        return InjectionPoint.NONE;
    }

    protected abstract void analyzeReturn(ClassContext classContext, Method method, InstructionHandle handle,
                                 ConstantPoolGen cpg, TaintFrame fact, String currentMethod)
            throws DataflowAnalysisException;
}
