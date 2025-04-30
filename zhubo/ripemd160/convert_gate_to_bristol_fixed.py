# convert_gate_to_bristol_fixed.py
# 专门处理 TinyGarble 导出的 output.gate.txt

gate_type_map = {
    'XOR': '2',
    'AND': '2',
    'OR': '2',
    'NOT': '1'
}

gates = []
wires = set()

with open('output.gate.txt', 'r') as f:
    for line in f:
        if line.strip() == "":
            continue
        tokens = line.strip().split()

        idx = 0
        while idx < len(tokens):
            op = tokens[idx]
            if op not in gate_type_map:
                idx += 1
                continue

            n_inputs = int(tokens[idx + 1])
            inputs = []
            for j in range(n_inputs):
                field = tokens[idx + 2 + j]
                if ":" in field:
                    wire = int(field.split(":")[1])
                else:
                    wire = int(field)
                inputs.append(wire)
                wires.add(wire)
            output_field = tokens[idx + 2 + n_inputs]
            if ":" in output_field:
                output = int(output_field.split(":")[1])
            else:
                output = int(output_field)
            wires.add(output)

            gates.append((inputs, output, op))
            idx += 2 + n_inputs + 1

n_wires = max(wires) + 1
n_inputs = 512
n_outputs = 160

with open('ripemd160.txt', 'w') as f:
    f.write(f"{len(gates)} {n_wires}\n")
    f.write(f"{n_inputs} 0 {n_outputs}\n")
    for gate in gates:
        inputs, output, op = gate
        f.write(f"{len(inputs)} 1 " + ' '.join(str(i) for i in inputs) + f" {output} {op}\n")
