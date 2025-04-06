import z3
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.translators.z3_ir import TranslatorZ3
from miasm.ir.symbexec import SymbolicExecutionEngine


MAIN = 0x00015ce

file_name = b"./plus_obf"
file_data = None
with open(file_name, "rb") as fp:
    file_data = bytearray(fp.read())

file_data_cpy = file_data.copy()
assert(file_data is not file_data_cpy)

print(len(file_data))

def can_jump_to_target(expr):
    if not expr.is_cond():
        return None

    # If the block doesnt contain any conditional jump dont process it
    jump_expr = expr.src1

    translator = TranslatorZ3()

    expr1 = translator.from_expr(expr)
    expr2 = translator.from_expr(jump_expr)

    solver = z3.Solver()

    solver.add(expr1 == expr2)

    return solver.check() == z3.sat


# Creating a state-map which keeps track of symbolic values
state_map = LocationDB()

# Opening the binary file for analysis
container = Container.from_string(file_data, state_map)

# XXX: Find out what this does
machine = Machine(container.arch)

# Initializing the disassembly framework
dis_engine = machine.dis_engine(
    container.bin_stream, # Passing the binary file contents
    loc_db = state_map)   # Passing the state-map

# Disassemble the block at the specified address
# function_dis = dis_engine.dis_block(MAIN)

# Disassemble all the blocks starting from this address for the
# current function
function_dis = dis_engine.dis_multiblock(MAIN)

# print(function_dis)

# Invoke the Miasm Intermediate Representation Engine
intermediate_repr = machine.lifter_model_call(dis_engine.loc_db)

# Translate the machine code to Miasm IR
ir_cfg = intermediate_repr.new_ircfg_from_asmcfg(function_dis)


predicate_count = 0

# Iterate over all the blocks of the current function
for block in function_dis.blocks:
    if len(block.lines) < 1:
        # Skipping the empty blocks
        continue

    # Create a Symbolic execution engine which will be helpful for symbolically
    # executing a block of IRs
    # VERY IMPORTANT: This needs to be inside of the for block else it will
    # give irrelevant results
    sym_engine = SymbolicExecutionEngine(intermediate_repr)

    # block.lines contains the individual instructions of the block
    # Kinda similar to how we do it in capstone
    # print(block)
    curr_block_addr = block.lines[0].offset


    # Create a symbolic representation of the block
    symbolic_expr = sym_engine.run_block_at(ir_cfg, curr_block_addr)

    # print(symbolic_expr)


    # if not symbolic_expr.is_cond():
    #    continue


    result = can_jump_to_target(symbolic_expr)
    if result == None:
        continue


    print(f"Current block is at: {curr_block_addr:#08x}", end = " ")

    # Block size = address of last instruction
    #            + size of last instruction
    #            - address of first_instruction
    # line.b gives us the actual bytes of the inst
    block_size = block.lines[-1].offset\
        + len(block.lines[-1].b)\
        - block.lines[0].offset

    predicate_count += 1
    print(dir(symbolic_expr))
    print(symbolic_expr.)
    break

    if len(block.lines) > 5:
        # We will only patch the last 6 instructions
        patch_start = block.lines[-6].offset
    else:
        # If the block is small, we will patch the whole block
        patch_start = curr_block_addr

    if result == True:
        # Jump will be to src1
        print(f"Jump is not taken")
        # If jump is not taken, then we can just nop it
        file_data_cpy[patch_start:patch_start + block_size] =\
            b"\x90" * (block_size)

    else:
        # Jump will be to src2
        print(f"Jump is taken")

        # Patch location will be the last instruction
        patch_location = block.lines[-1].offset

        jmp_offset = int(str(symbolic_expr.src2), 16) - patch_location - 2

        print(f"Jumping from {patch_location:#08x} -> {int(str(symbolic_expr.src2), 16):#08x}")

        # Patch the whole block to NOPs
        file_data_cpy[patch_start:patch_start + block_size - 2] =\
            b"\x90" * (block_size - 2)

        # Patch the conditional jump to be an indirect jump "jmp"
        file_data_cpy[patch_location:patch_location + 2] = b"\xeb"\
            + int.to_bytes(jmp_offset, length = 1, byteorder = "little")


print(len(file_data_cpy))
assert(len(file_data_cpy) == 14_472)

print(f"Total: {predicate_count}")

with open("layer2", "wb") as fp:
    fp.write(file_data_cpy)

