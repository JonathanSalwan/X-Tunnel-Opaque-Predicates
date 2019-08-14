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
COLOR = 0x000055 # IDA color



def branch(inst, node, startEA):
    global nb_op

    isOP = False
    sat  = ctx.isSat(node)
    if sat == False and node.isSymbolized():
        isOP = True
        print('[+] Opaque predicat found at 0x%x (always %s)' %(startEA, repr(inst.isConditionTaken())))
        nb_op += 1

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
    ctx.setArchitecture(ARCH.X86_64)
    ctx.enableMode(MODE.ALIGNED_MEMORY, True)
    ctx.addCallback(handle_mem_read, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
    names = dict()

    # Symbolize registers
    for r in ctx.getParentRegisters():
        var = ctx.convertRegisterToSymbolicVariable(r)
        names.update({var.getName() : str(r)})

    ip = startEA
    for _ in range(1000):
        # Get opcodes from IDA and exectue them into Triton
        inst = Instruction()
        opcode = idc.GetManyBytes(ip, 16)
        inst.setOpcode(opcode)
        inst.setAddress(ip)
        ctx.processing(inst)

        # Get next instruction
        ip = ctx.getSymbolicRegisterValue(ctx.registers.rip)

        nb_in += 1

        # Handle external calls
        if inst.getType() == OPCODE.X86.CALL:
            var = ctx.convertRegisterToSymbolicVariable(ctx.registers.rax)
            names.update({var.getName() : '%s from call at %x' %(str(ctx.registers.rax), ip)})
            ip = inst.getNextAddress()

        elif inst.isBranch() or ip == endEA:
            if inst.isBranch() and inst.getType() != OPCODE.X86.JMP:
                nb_ed += 1
            break

    # Get path constraint
    ast = ctx.getAstContext()
    pc  = ctx.getPathConstraintsAst()

    # Get model to detect opaque predicate
    return branch(inst, ast.lnot(pc), startEA)


# Analyse all BB of the function
func = get_func(ScreenEA())
bbs  = FlowChart(func)
st   = time.time()

for bb in bbs:
    nb_bb += 1
    print('[+] Analyzing basic block at 0x%x' %(bb.startEA))
    try:
        isOP = prove_bb(bb.startEA, bb.endEA)
    except:
        continue
    if isOP:
        for ea in range(bb.startEA, bb.endEA):
            SetColor(ea, CIC_ITEM, COLOR)

et = time.time()

print('[+] Basic Blocks analyzed     : %d' %(nb_bb))
print('[+] Edges analyzed            : %d' %(nb_ed))
print('[+] Instructions executed     : %d' %(nb_in))
print('[+] Opaque predicats found    : %d' %(nb_op))
print('[+] Time analysis             : %s seconds' %(et - st))
