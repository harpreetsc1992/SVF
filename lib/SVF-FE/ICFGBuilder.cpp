//===- ICFGBuilder.cpp ----------------------------------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//


/*
 * ICFGBuilder.cpp
 *
 *  Created on:
 *      Author: yulei
 */

#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/ICFGBuilder.h"
#include "Graphs/PAG.h"
#include "SVF-FE/PAGBuilder.h"
#include "Graphs/ICFG.h"
#include "llvm/IR/Instruction.h"

using namespace SVF;
using namespace SVFUtil;

/*!
 * Create ICFG nodes and edges
 */
void ICFGBuilder::build(SVFModule* svfModule)
{
    for (SVFModule::const_iterator iter = svfModule->begin(), eiter = svfModule->end(); iter != eiter; ++iter)
    {
        const SVFFunction *fun = *iter;
        if (SVFUtil::isExtCall(fun))
            continue;
        WorkList worklist;
        processFunEntry(fun,worklist);
        processFunBody(worklist);
        processFunExit(fun);
    }
    connectGlobalToProgEntry(svfModule);
}

/*!
 * function entry
 */
void ICFGBuilder::processFunEntry(const SVFFunction*  fun, WorkList& worklist)
{
    FunEntryBlockNode* FunEntryBlockNode = icfg->getFunEntryBlockNode(fun);
    const Instruction* entryInst = &((fun->getLLVMFun()->getEntryBlock()).front());
    InstVec insts;
    if (isIntrinsicInst(entryInst))
        getNextInsts(entryInst, insts);
    else
        insts.push_back(entryInst);
    for (InstVec::const_iterator nit = insts.begin(), enit = insts.end();
            nit != enit; ++nit)
    {
        ICFGNode* instNode = getOrAddBlockICFGNode(*nit);           //add interprocedure edge
        icfg->addIntraEdge(FunEntryBlockNode, instNode);
        worklist.push(*nit);
    }
}

void
annotateBlockInst(BasicBlock *su, NodeLabel *brI, std::vector<Value*> cmpOp)
{
    NodeLabel *currInst;
    for (const Instruction &inst: *su)
    {
        currInst = new NodeLabel(brI->getInst(), &inst, brI->getLabel());
        currInst->copyLabel(brI);
        for (auto &ops: cmpOp)
        {
            currInst->addOperand((Value*)ops);
        }
        errs() << "Parent Condition: " << *(currInst->getParentBranch()) << 
            "\nCurrent Instruction: " << *(currInst->getInst()) << 
            "\nBranch Label: " << currInst->getLabel() << 
            "\n1st Operand: " << *(currInst->getOperand1()) << 
            "\n2nd Operand: " << *(currInst->getOperand2()) << "\n";

        if (auto *loadInst = SVFUtil::dyn_cast<LoadInst>(&inst))
        {
            
        }
        if (auto *storeInst = SVFUtil::dyn_cast<StoreInst>(&inst))
        {
        }
    }
}

void
annotateInst(BasicBlock *su, ICFGNode* sNode, NodeLabel *brInst, std::vector<Value*> cmpOp)
{
    StringRef thenInst = StringRef("if.then");
    StringRef endInst = StringRef("if.end");
    StringRef elseInst = StringRef("if.else");
    
    annotateBlockInst(su, brInst, cmpOp);
}

/*!
 * function body
 */
void ICFGBuilder::processFunBody(WorkList& worklist)
{
    BBSet visited;
    NodeLabel *currNode;
    StringRef thenInst = StringRef("if.then");
    StringRef endInst = StringRef("if.end");
    StringRef elseInst = StringRef("if.else");
        std::vector<Value*> cmpOp;
    /// function body
    while (!worklist.empty())
    {
        const Instruction* inst = worklist.pop();
        if (visited.find(inst) == visited.end())
        {
            visited.insert(inst);
            ICFGNode* srcNode = getOrAddBlockICFGNode(inst);
            if (isReturn(inst))
            {
                const Function* fun = inst->getFunction();
                const SVFFunction* svfFun = LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(fun);
                FunExitBlockNode* FunExitBlockNode = icfg->getFunExitBlockNode(svfFun);
                icfg->addIntraEdge(srcNode, FunExitBlockNode);
            }
            InstVec nextInsts;
            getNextInsts(inst, nextInsts);
            int loop = 2;
            for (InstVec::const_iterator nit = nextInsts.begin(), enit =
                        nextInsts.end(); nit != enit; ++nit)
            {
                const Instruction* succ = *nit;
                ICFGNode* sNode = getOrAddBlockICFGNode(succ);
                std::map<ICFGNode *, int> curBr;
                if (auto *cmpInst = SVFUtil::dyn_cast<CmpInst>(succ))
                {
                    cmpOp.clear(); 
                    for (int i = 0; i < succ->getNumOperands(); i++)
                    {
                        ICFGNode* dNode = getOrAddBlockICFGNode(SVFUtil::dyn_cast<Instruction>(succ->getOperand(i)));
                        icfg->addIntraEdge(dNode, sNode);
                        cmpOp.push_back(succ->getOperand(i));
                    }
                }
                else if (auto *brInst = SVFUtil::dyn_cast<BranchInst>(succ))
                {
                    curBr.insert(std::pair<ICFGNode*, int>(sNode, ++loop));
                    StringRef instName = succ->getOperand(0)->getName();
                    BasicBlock *bbBranch = (BasicBlock *)succ->getParent();
                    
                    int counter = 2;
                    for (BasicBlock *su : successors(bbBranch)) 
                    {
                        if (counter > 0) {
                            currNode = new NodeLabel((Instruction *)succ, (Instruction *)succ, su->getName());
                            annotateInst(su, sNode, currNode, cmpOp);
                            counter--;
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                else
                {
                }
//                if (auto *loadInst = SVFUtil::dyn_cast<LoadInst>(succ))
//                {
//                    ICFGNode* sNode = getOrAddBlockICFGNode(succ);
//                    for (int i = 0; i < succ->getNumOperands(); i++)
//                    {
//                        ICFGNode* dNode = getOrAddBlockICFGNode(SVFUtil::dyn_cast<Instruction>(succ->getOperand(i)));
//                        icfg->addIntraEdge(sNode, dNode);
//                        errs() << "Source::" << *sNode << "\n";
//                        errs() << "Dest  ::" << *dNode << "\n";
//                    }
//                }
//                if (auto *storeInst = SVFUtil::dyn_cast<StoreInst>(succ))
//                {
//                }
//                if (auto *binaryInst = SVFUtil::dyn_cast<BinaryOperator>(succ))
//                {
//                }
                ICFGNode* dstNode = getOrAddBlockICFGNode(succ);
                if (isNonInstricCallSite(inst))
                {
                    RetBlockNode* retICFGNode = getOrAddRetICFGNode(inst);
                    icfg->addIntraEdge(srcNode, retICFGNode);
                    srcNode = retICFGNode;
                }
                icfg->addIntraEdge(srcNode, dstNode);
                worklist.push(succ);
            }
        }
    }
}

/*!
 * function exit e.g., exit(0). In LLVM, it usually manifests as "unreachable" instruction
 * If a function has multiple exit(0), we will only have one "unreachle" instruction
 * after the UnifyFunctionExitNodes pass.
 */
void ICFGBuilder::processFunExit(const SVFFunction*  fun)
{
    FunExitBlockNode* FunExitBlockNode = icfg->getFunExitBlockNode(fun);
    const Instruction* exitInst = &(getFunExitBB(fun->getLLVMFun())->back());
    InstVec insts;
    if (isIntrinsicInst(exitInst))
        getPrevInsts(exitInst, insts);
    else
        insts.push_back(exitInst);
    for (InstVec::const_iterator nit = insts.begin(), enit = insts.end();
            nit != enit; ++nit)
    {
        ICFGNode* instNode = getOrAddBlockICFGNode(*nit);
        icfg->addIntraEdge(instNode, FunExitBlockNode);
    }
}




/*!
 * (1) Add and get CallBlockICFGNode
 * (2) Handle call instruction by creating interprocedural edges
 */
InterBlockNode* ICFGBuilder::getOrAddInterBlockICFGNode(const Instruction* inst)
{
    assert(SVFUtil::isCallSite(inst) && "not a call instruction?");
    assert(SVFUtil::isNonInstricCallSite(inst) && "associating an intrinsic debug instruction with an ICFGNode!");
    CallBlockNode* callICFGNode = getOrAddCallICFGNode(inst);
    if (const SVFFunction*  callee = getCallee(inst))
        addICFGInterEdges(inst, callee);                       //creating interprocedural edges
    return callICFGNode;
}

/*!
 * Create edges between ICFG nodes across functions
 */
void ICFGBuilder::addICFGInterEdges(const Instruction* cs, const SVFFunction* callee)
{
    CallBlockNode* CallBlockNode = getOrAddCallICFGNode(cs);
    FunEntryBlockNode* calleeEntryNode = icfg->getFunEntryBlockNode(callee);
    icfg->addCallEdge(CallBlockNode, calleeEntryNode, cs);

    if (!isExtCall(callee))
    {
        RetBlockNode* retBlockNode = getOrAddRetICFGNode(cs);
        FunExitBlockNode* calleeExitNode = icfg->getFunExitBlockNode(callee);
        icfg->addRetEdge(calleeExitNode, retBlockNode, cs);
    }
}

void ICFGBuilder::connectGlobalToProgEntry(SVFModule* svfModule)
{
    const SVFFunction* mainFunc = SVFUtil::getProgEntryFunction(svfModule);

    /// Return back if the main function is not found, the bc file might be a library only
    if(mainFunc == NULL)
        return;

    FunEntryBlockNode* entryNode = icfg->getFunEntryBlockNode(mainFunc);
    GlobalBlockNode* globalNode = icfg->getGlobalBlockNode();
    IntraCFGEdge* intraEdge = new IntraCFGEdge(entryNode,globalNode);
    icfg->addICFGEdge(intraEdge);
}

