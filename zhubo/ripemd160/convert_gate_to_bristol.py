# convert_cbmcgc_gate_to_bristol.py
# 把 CBMC-GC output.gate.txt 转成 bristol format
input_file = "output.gate.txt"
output_file = "ripemd160_bristol.txt"

# 统计总gate数
with open(input_file, "r") as f:
    lines = [line.strip() for line in f if line.strip() != ""]

n_gates = len(lines)

# 根据 output.inputs.txt 获取输入输出信息
with open("output.inputs.txt", "r") as f:
    header = f.readline().strip()
    inputs = list(map(int, header.split()))
    total_inputs = sum(inputs)
    output_line = f.readline().strip()
    total_outputs = int(output_line)

with open(output_file, "w") as f:
    f.write(f"{n_gates} {total_inputs}\n")
    f.write(f"{total_inputs} 0 {total_outputs}\n")
    for line in lines:
        tokens = line.split()
        gate_type = tokens[0]
        if gate_type == "XOR":
            n_inputs = int(tokens[1])
            input_wires = []
            for i in range(n_inputs):
                idx = tokens[2 + i]
                input_wires.append(idx.split(":")[1])
            output_wire = tokens[2 + n_inputs].split(":")[1]
            f.write(f"{n_inputs} 1 {' '.join(input_wires)} {output_wire} XOR\n")
        elif gate_type == "AND":
            n_inputs = int(tokens[1])
            input_wires = []
            for i in range(n_inputs):
                idx = tokens[2 + i]
                input_wires.append(idx.split(":")[1])
            output_wire = tokens[2 + n_inputs].split(":")[1]
            f.write(f"{n_inputs} 1 {' '.join(input_wires)} {output_wire} AND\n")
        elif gate_type == "OR":
            n_inputs = int(tokens[1])
            input_wires = []
            for i in range(n_inputs):
                idx = tokens[2 + i]
                input_wires.append(idx.split(":")[1])
            output_wire = tokens[2 + n_inputs].split(":")[1]
            f.write(f"{n_inputs} 1 {' '.join(input_wires)} {output_wire} OR\n")
        elif gate_type == "NOT":
            n_inputs = int(tokens[1])
            input_wire = tokens[2].split(":")[1]
            output_wire = tokens[3].split(":")[1]
            f.write(f"1 1 {input_wire} {output_wire} INV\n")
        else:
            print(f"Unsupported gate type: {gate_type}")
