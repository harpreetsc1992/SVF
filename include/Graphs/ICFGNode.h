//===- ICFGNode.h -- ICFG node------------------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2018>  <Yulei Sui>
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
 * ICFGNode.h
 *
 *  Created on: Sep 11, 2018
 *      Author: Yulei
 */

#ifndef ICFGNODE_H_
#define ICFGNODE_H_

#include "Util/SVFUtil.h"
#include "Graphs/GenericGraph.h"
#include "Graphs/ICFGEdge.h"

using namespace std;

#define VECTORSZ 64

namespace SVF
{

class ICFGNode;
class RetBlockNode;
class CallPE;
class RetPE;
class PAGEdge;
class PAGNode;
class VFGNode;

/*!
 * Interprocedural control-flow graph node, representing different kinds of program statements
 * including top-level pointers (ValPN) and address-taken objects (ObjPN)
 */
typedef GenericNode<ICFGNode, ICFGEdge> GenericICFGNodeTy;

class ICFGNode : public GenericICFGNodeTy
{

public:
    /// 22 kinds of ICFG node
    /// Gep represents offset edge for field sensitivity
    enum ICFGNodeK
    {
        IntraBlock, FunEntryBlock, FunExitBlock, FunCallBlock, FunRetBlock, GlobalBlock
    };

    typedef ICFGEdge::ICFGEdgeSetTy::iterator iterator;
    typedef ICFGEdge::ICFGEdgeSetTy::const_iterator const_iterator;
    typedef Set<const CallPE *> CallPESet;
    typedef Set<const RetPE *> RetPESet;
    typedef std::list<const VFGNode*> VFGNodeList;

private:
    //std::map<const NodeID, std::vector<std::bitset<VECTORSZ> > > label;
    //std::map<const NodeID, std::bitset<VECTORSZ> > label;
    std::map<const NodeID, uint64_t > label;
    NodeID parBrId;
    //std::vector<std::bitset<VECTORSZ> > v;
    //std::bitset<VECTORSZ> v;
    uint64_t v;
//    NodeID label;

public:
    /// Constructor
    ICFGNode(NodeID i, ICFGNodeK k) : GenericICFGNodeTy(i, k), fun(NULL), bb(NULL)
    {

    }

    /// Return the function of this ICFGNode
    virtual const SVFFunction* getFun() const
    {
        return fun;
    }

    /// Return the function of this ICFGNode
    virtual const BasicBlock* getBB() const
    {
        return bb;
    }

    inline void setParBrId(ICFGNode* node, NodeID brId)
    {
        node->parBrId = brId;
    }

    inline NodeID getParBrId(ICFGNode* node)
    {
        return node->parBrId;
    }

    /// Overloading operator << for dumping ICFG node ID
    //@{
    friend raw_ostream &operator<<(raw_ostream &o, const ICFGNode &node)
    {
        o << node.toString();
        return o;
    }
    //@}

    /// Set/Get methods of VFGNodes
    ///@{
    inline void addVFGNode(const VFGNode *vfgNode)
    {
        VFGNodes.push_back(vfgNode);
    }

    inline const VFGNodeList& getVFGNodes() const
    {
        return VFGNodes;
    }
    ///@}

    inline ICFGNode* endLabel(ICFGNode* node)
    {
        const NodeID id = node->getId();
        node->v = node->v & 0;
        //v[id] = v[id] >> 64;
        //v[id][0] = 0;
        //(node->label).insert(std::pair<NodeID, std::vector<std::bitset<VECTORSZ> > >(id, node->v));
        //(node->label).insert(std::pair<NodeID, std::bitset<VECTORSZ> >(id, node->v));
        (node->label).insert(std::pair<NodeID, uint64_t >(id, node->v));
        return node;
    }

    inline ICFGNode* toggleLabel(ICFGNode* node, uint8_t cond)
    {
        const NodeID id = node->getId();
        int valset = 0;
        int i = 0;
        //for (i = 0; i < VECTORSZ; i++) {
            //if (v[i] == 1) {
                //valset = 1;
                //break;
            //}
        //}
        //node->v[id] = (i < 63) ? node->v[id] << 1: node->v[id];
        node->v = node->v << 1;
        node->v = node->v | (uint64_t) cond;
        //v.push_back(b);
        //(node->label).insert(std::pair<NodeID, std::vector<std::bitset<VECTORSZ> > >(id, node->v));
        //(node->label).insert(std::pair<NodeID, std::bitset<VECTORSZ> >(id, node->v));
        (node->label).insert(std::pair<NodeID, uint64_t >(id, node->v));
//        (node->label).insert((node->label).at(id) ^ 1);
        return node;
    }

    inline int verifyLabel(const ICFGNode* node)
    {
        const NodeID id = node->getId();
        const auto iter = (node->label).find(id);
    
        //if(iter != (node->label).end()) return iter->second;
        //else                            return 0;
    }
 
    virtual const std::string toString() const;

protected:
    const SVFFunction* fun;
    const BasicBlock* bb;
    VFGNodeList VFGNodes; //< a set of VFGNodes

};


class NodeLabel
{
private: 
    const Instruction* prevBr;
    const Instruction* currInst;
    StringRef parLabel;
    std::vector<Value *> operands;
    uint8_t isTaken = 0;
public:
    NodeLabel() {}
    NodeLabel(const Instruction* brI, const Instruction* i, StringRef parent) : currInst(i), prevBr(brI), parLabel(parent) {
    }

    const Instruction* getParentBranch()
    {
        return this->prevBr;
    }

    StringRef getLabel()
    {
        return this->parLabel;
    }

    uint8_t checkBranch()
    {
        return this->isTaken;
    }
    
    const Instruction* getInst()
    {
        return this->currInst;
    }

    Value* getOperand1()
    {
        return this->operands.at(0);
    }

    Value* getOperand2()
    {
        return this->operands.at(1);
    }

    void addOperand(Value* v)
    {
        (this->operands).push_back(v);
    }

    void setLabel(StringRef iName)
    {
        this->parLabel = iName;
    }
   
    void copyLabel(NodeLabel *brLabel)
    {
        this->isTaken = brLabel->isTaken;
    }

    void setBrLabel(uint8_t decision)
    {
        this->isTaken = decision;
    }
};


/*!
 * Unique ICFG node stands for all global initializations
 */
class GlobalBlockNode : public ICFGNode
{

public:
    GlobalBlockNode(NodeID id) : ICFGNode(id, GlobalBlock)
    {
    	bb = NULL;
    }

    /// Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const GlobalBlockNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == GlobalBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == GlobalBlock;
    }
    //@}

    virtual const std::string toString() const;
};

/*
  IntraBlock Node for Memory operations
*/

class IntraMemNode : public ICFGNode
{
private:
    const Instruction *inst;

public:
    IntraMemNode(NodeID id, const Instruction *i) : ICFGNode(id, IntraBlock), inst(i)
    {
        fun = LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(inst->getFunction());
        bb = inst->getParent();
    }

    inline const Instruction *getInst() const
    {
        return inst;
    }

    /// Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const IntraMemNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == IntraBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == IntraBlock;
    }
    //@}

    const std::string toString() const;
};

/*!
 * ICFG node stands for a program statement
 */
class IntraBlockNode : public ICFGNode
{
private:
    const Instruction *inst;
//    int label = 0;

public:
    IntraBlockNode(NodeID id, const Instruction *i) : ICFGNode(id, IntraBlock), inst(i)
    {
        fun = LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(inst->getFunction());
        bb = inst->getParent();
    }

    inline const Instruction *getInst() const
    {
        return inst;
    }

    /// Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const IntraBlockNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == IntraBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == IntraBlock;
    }
    //@}

    const std::string toString() const;
};

class InterBlockNode : public ICFGNode
{

public:
    /// Constructor
    InterBlockNode(NodeID id, ICFGNodeK k) : ICFGNode(id, k)
    {
    }

    /// Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const InterBlockNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == FunEntryBlock
               || node->getNodeKind() == FunExitBlock
               || node->getNodeKind() == FunCallBlock
               || node->getNodeKind() == FunRetBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == FunEntryBlock
               || node->getNodeKind() == FunExitBlock
               || node->getNodeKind() == FunCallBlock
               || node->getNodeKind() == FunRetBlock;
    }
    //@}
};


/*!
 * Function entry ICFGNode containing a set of FormalParmVFGNodes of a function
 */
class FunEntryBlockNode : public InterBlockNode
{

public:
    typedef std::vector<const PAGNode *> FormalParmNodeVec;
private:
    FormalParmNodeVec FPNodes;
public:
    FunEntryBlockNode(NodeID id, const SVFFunction* f);

    /// Return function
    inline const SVFFunction* getFun() const
    {
        return fun;
    }

    /// Return the set of formal parameters
    inline const FormalParmNodeVec &getFormalParms() const
    {
        return FPNodes;
    }

    /// Add formal parameters
    inline void addFormalParms(const PAGNode *fp)
    {
        FPNodes.push_back(fp);
    }

    ///Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const FunEntryBlockNode *)
    {
        return true;
    }

    static inline bool classof(const InterBlockNode *node)
    {
        return node->getNodeKind() == FunEntryBlock;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == FunEntryBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == FunEntryBlock;
    }
    //@}

    const virtual std::string toString() const;
};

/*!
 * Function exit ICFGNode containing (at most one) FormalRetVFGNodes of a function
 */
class FunExitBlockNode : public InterBlockNode
{

private:
    const SVFFunction* fun;
    const PAGNode *formalRet;
public:
    FunExitBlockNode(NodeID id, const SVFFunction* f);

    /// Return function
    inline const SVFFunction* getFun() const
    {
        return fun;
    }

    /// Return actual return parameter
    inline const PAGNode *getFormalRet() const
    {
        return formalRet;
    }

    /// Add actual return parameter
    inline void addFormalRet(const PAGNode *fr)
    {
        formalRet = fr;
    }

    ///Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const FunEntryBlockNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == FunExitBlock;
    }

    static inline bool classof(const InterBlockNode *node)
    {
        return node->getNodeKind() == FunExitBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == FunExitBlock;
    }
    //@}

    virtual const std::string toString() const;
};

/*!
 * Call ICFGNode containing a set of ActualParmVFGNodes at a callsite
 */
class CallBlockNode : public InterBlockNode
{

public:
    typedef std::vector<const PAGNode *> ActualParmVFGNodeVec;
private:
    const Instruction* cs;
    const RetBlockNode* ret;
    ActualParmVFGNodeVec APNodes;
public:
    CallBlockNode(NodeID id, const Instruction* c) : InterBlockNode(id, FunCallBlock), cs(c), ret(NULL)
    {
        fun = LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(cs->getFunction());
        bb = cs->getParent();
    }

    /// Return callsite
    inline const Instruction* getCallSite() const
    {
        return cs;
    }

    /// Return callsite
    inline const RetBlockNode* getRetBlockNode() const
    {
    	assert(ret && "RetBlockNode not set?");
        return ret;
    }

    /// Return callsite
    inline void setRetBlockNode(const RetBlockNode* r)
    {
        ret = r;
    }

    /// Return callsite
    inline const SVFFunction* getCaller() const
    {
        return LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(cs->getFunction());
    }

    /// Return Basic Block
    inline const BasicBlock* getParent() const
    {
        return cs->getParent();
    }

    /// Return true if this is an indirect call
    inline bool isIndirectCall() const
    {
        return NULL == SVFUtil::getCallee(cs);
    }

    /// Return the set of actual parameters
    inline const ActualParmVFGNodeVec &getActualParms() const
    {
        return APNodes;
    }

    /// Add actual parameters
    inline void addActualParms(const PAGNode *ap)
    {
        APNodes.push_back(ap);
    }

    ///Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const CallBlockNode *)
    {
        return true;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == FunCallBlock;
    }

    static inline bool classof(const InterBlockNode *node)
    {
        return node->getNodeKind() == FunCallBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == FunCallBlock;
    }
    //@}

    virtual const std::string toString() const;
};


/*!
 * Return ICFGNode containing (at most one) ActualRetVFGNode at a callsite
 */
class RetBlockNode : public InterBlockNode
{

private:
    const Instruction* cs;
    const PAGNode *actualRet;
    const CallBlockNode* callBlockNode;
public:
    RetBlockNode(NodeID id, const Instruction* c, CallBlockNode* cb) :
        InterBlockNode(id, FunRetBlock), cs(c), actualRet(NULL), callBlockNode(cb)
    {
        fun = LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(cs->getFunction());
        bb = cs->getParent();
    }

    /// Return callsite
    inline const Instruction* getCallSite() const
    {
        return cs;
    }

    inline const CallBlockNode* getCallBlockNode() const
    {
        return callBlockNode;
    }
    /// Return actual return parameter
    inline const PAGNode *getActualRet() const
    {
        return actualRet;
    }

    /// Add actual return parameter
    inline void addActualRet(const PAGNode *ar)
    {
        actualRet = ar;
    }

    ///Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const RetBlockNode *)
    {
        return true;
    }

    static inline bool classof(const InterBlockNode *node)
    {
        return node->getNodeKind() == FunRetBlock;
    }

    static inline bool classof(const ICFGNode *node)
    {
        return node->getNodeKind() == FunRetBlock;
    }

    static inline bool classof(const GenericICFGNodeTy *node)
    {
        return node->getNodeKind() == FunRetBlock;
    }
    //@}

    virtual const std::string toString() const;
};

} // End namespace SVF

#endif /* ICFGNode_H_ */
