#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
## Tested with IDA 7.3 and Triton commit bd738d018de511a5cc66cb4b6870d376145de605
##

import time

from idautils   import *
from idaapi     import *
from idc        import *
from triton     import *

ctx   = None     # Triton context
names = None     # Used for model (if needed) to map a symvar to its name
nb_bb = 0        # number of basic blocks analyzed
nb_op = 0        # number of opaque predicates found
nb_ed = 0        # number of edge
nb_in = 0        # number of instruction executed
nb_to = 0        # number of timeout
COLOR = 0x000055 # IDA color
M64   = False    # Is a x86_64 binary ?


def branch(ast, inst, node, startEA):
    global nb_op

    sat   = ctx.isSat(node)
    isOP  = False

    if sat == False and node.isSymbolized():
        isOP = True
        print('[+] Opaque predicat found at 0x%x (always %s)' %(startEA, repr(inst.isConditionTaken())))
        nb_op += 1
        #land = node.getChildren()[0]
        #ite1 = land.getChildren()[1]
        #ite2 = ite1.getChildren()[0]
        #cond = ite2.getChildren()[0]
        #fd = open("/tmp/opaques", "a+")
        #fd.write(str(ast.unrollAst(cond)) + '\n')
        #fd.close()

    return isOP


def handle_mem_read(ctx, mem):
    global names
    for i in range(mem.getSize()):
        memi = MemoryAccess(mem.getAddress()+i, CPUSIZE.BYTE)
        var = ctx.convertMemoryToSymbolicVariable(memi)
        names.update({var.getName() : str(memi)})


def prove_bb(startEA, endEA):
    global ctx
    global names
    global nb_ed
    global nb_in
    global nb_to

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64 if M64 else ARCH.X86)
    ctx.enableMode(MODE.ALIGNED_MEMORY, True)
    ctx.addCallback(handle_mem_read, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    names = dict()

    # Symbolize registers
    for r in ctx.getParentRegisters():
        var = ctx.convertRegisterToSymbolicVariable(r)
        names.update({var.getName() : str(r)})

    ip = startEA
    c  = 0
    for _ in range(40):
        # Get opcodes from IDA and exectue them into Triton
        inst = Instruction()
        opcode = idc.GetManyBytes(ip, 16)
        inst.setOpcode(opcode)
        inst.setAddress(ip)
        ctx.processing(inst)

        # Get next instruction
        ip = ctx.getSymbolicRegisterValue(ctx.registers.rip if M64 else ctx.registers.eip)

        nb_in += 1

        # Handle external calls
        if inst.getType() == OPCODE.X86.CALL:
            retr = ctx.registers.rax if M64 else ctx.registers.eax
            var  = ctx.convertRegisterToSymbolicVariable(retr)
            names.update({var.getName() : '%s from call at %x' %(str(retr), ip)})
            ip = inst.getNextAddress()

        elif inst.isBranch() or ip == endEA:
            if inst.isBranch() and inst.getType() != OPCODE.X86.JMP:
                nb_ed += 1
            break
        c += 1

    # Timeout if more than 40 inst
    if c >= 40:
        nb_to += 1

    # Get path constraint
    ast = ctx.getAstContext()
    pc  = ctx.getPathConstraintsAst()

    # Get model to detect opaque predicate
    return branch(ast, inst, ast.lnot(pc), startEA)


c  = 1
st = time.time()
for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        # Analyse all BB of the function
        func = get_func(funcea)
        bbs  = FlowChart(func)
        for bb in bbs:
            nb_bb += 1
            print('[+] Analyzing basic block at 0x%x (function %d)' %(bb.startEA, c))
            try:
                isOP = prove_bb(bb.startEA, bb.endEA)
            except:
                continue
            if isOP:
                for ea in range(bb.startEA, bb.endEA):
                    SetColor(ea, CIC_ITEM, COLOR)
        c += 1
et = time.time()

print('[+] Basic Blocks analyzed     : %d' %(nb_bb))
print('[+] Edges analyzed            : %d' %(nb_ed))
print('[+] Instructions executed     : %d' %(nb_in))
print('[+] Opaque predicats found    : %d' %(nb_op))
print('[+] Number of timeout         : %d' %(nb_to))
print('[+] Time analysis             : %s seconds' %(et - st))
