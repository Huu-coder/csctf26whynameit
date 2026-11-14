#!/usr/bin/env python3
"""Golem - GASM interpreter proof of concept.

Summary: the audit service presents 100 deterministic GASM programs; a
faithful interpreter (16-bit registers, nested rep/ifz/ifn, documented
div/mod-by-zero and exhausted-input edge cases) answers every round.

Usage: golem.py HOST PORT          answer rounds from the live service
       golem.py --test EXAMPLES    verify the interpreter against examples.txt

The CTF instance is retired; this PoC documents the exploit path.
"""

import socket
import sys

MASK = 0xFFFF


def parse_program(lines):
    root = []
    stack = [root]
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        op = parts[0]
        if op in ("rep", "ifz", "ifn"):
            node = (op, parts[1:], [])
            stack[-1].append(node)
            stack.append(node[2])
        elif op == "end":
            if len(stack) == 1:
                raise ValueError("unmatched end")
            stack.pop()
        else:
            stack[-1].append((op, parts[1:]))
    if len(stack) != 1:
        raise ValueError("unclosed block")
    return root


def reg(token):
    if not token.startswith("r"):
        raise ValueError(f"bad register: {token}")
    index = int(token[1:])
    if not 0 <= index < 16:
        raise ValueError(f"bad register: {token}")
    return index


def execute(program, tape):
    regs = [0] * 16
    output = []
    input_pos = 0

    def run(nodes):
        nonlocal input_pos
        for node in nodes:
            op, args = node[0], node[1]
            if op == "rep":
                for _ in range(int(args[0])):
                    run(node[2])
                continue
            if op in ("ifz", "ifn"):
                value = regs[reg(args[0])]
                if (value == 0) == (op == "ifz"):
                    run(node[2])
                continue

            if op == "set":
                regs[reg(args[0])] = int(args[1]) & MASK
            elif op == "mov":
                regs[reg(args[0])] = regs[reg(args[1])]
            elif op in ("add", "sub", "mul", "div", "mod",
                        "and", "or", "xor", "shl", "shr"):
                dst, left, right = reg(args[0]), regs[reg(args[1])], regs[reg(args[2])]
                if op == "add":
                    value = left + right
                elif op == "sub":
                    value = left - right
                elif op == "mul":
                    value = left * right
                elif op == "div":
                    value = 0xFFFF if right == 0 else left // right
                elif op == "mod":
                    value = left if right == 0 else left % right
                elif op == "and":
                    value = left & right
                elif op == "or":
                    value = left | right
                elif op == "xor":
                    value = left ^ right
                elif op == "shl":
                    value = left << (right & 15)
                else:  # shr
                    value = left >> (right & 15)
                regs[dst] = value & MASK
            elif op == "not":
                regs[reg(args[0])] = (~regs[reg(args[1])]) & MASK
            elif op == "in":
                if input_pos < len(tape):
                    regs[reg(args[0])] = tape[input_pos]
                    input_pos += 1
                else:
                    regs[reg(args[0])] = MASK  # exhausted input reads 0xFFFF
            elif op == "out":
                output.append(regs[reg(args[0])])
            else:
                raise ValueError(f"unknown op: {op}")

    run(program)
    return output


def parse_examples(path):
    examples = []
    with open(path, encoding="ascii") as fh:
        lines = fh.read().splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() != "PROGRAM":
            i += 1
            continue
        i += 1
        program = []
        while lines[i].strip() != ".":
            program.append(lines[i])
            i += 1
        i += 1
        tape = [int(x) for x in lines[i].removeprefix("INPUT ").split()]
        expected = [int(x) for x in lines[i + 1].removeprefix("OUTPUT ").split()]
        i += 2
        examples.append((program, tape, expected))
    return examples


def test_examples(path):
    failures = 0
    for index, (lines, tape, expected) in enumerate(parse_examples(path), 1):
        actual = execute(parse_program(lines), tape)
        if actual != expected:
            failures += 1
            print(f"example {index}: got {actual}, expected {expected}", file=sys.stderr)
    print("all examples passed" if not failures else f"{failures} example(s) failed")
    raise SystemExit(1 if failures else 0)


def read_line(sock, pending):
    while b"\n" not in pending:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("server closed connection")
        pending += chunk
    line, pending = pending.split(b"\n", 1)
    return line.decode().rstrip("\r"), pending


def solve(host, port):
    with socket.create_connection((host, port), timeout=10) as sock:
        pending = b""
        while True:
            while b"=== round " not in pending:
                chunk = sock.recv(4096)
                if not chunk:
                    sys.stdout.write(pending.decode(errors="replace"))
                    return
                pending += chunk
            start = pending.index(b"=== round ")
            sys.stdout.write(pending[:start].decode(errors="replace"))
            pending = pending[start:]

            while True:  # consume the "=== round N ===" line itself
                line, pending = read_line(sock, pending)
                if line == "PROGRAM":
                    break
            program_lines = []
            while True:
                line, pending = read_line(sock, pending)
                if line == ".":
                    break
                program_lines.append(line)
            while True:
                line, pending = read_line(sock, pending)
                if line.startswith("INPUT"):
                    break
            tape = [int(x) for x in line[6:].split()]

            while b"OUTPUT>" not in pending:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("server closed before prompt")
                pending += chunk
            marker = pending.index(b"OUTPUT>")
            sys.stdout.write(pending[:marker].decode(errors="replace"))
            pending = pending[marker + len(b"OUTPUT>"):]

            answer = execute(parse_program(program_lines), tape)
            sock.sendall((" ".join(map(str, answer)) + "\n").encode())
            print(f"answered {len(answer)} values", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--test":
        test_examples(sys.argv[2])
    elif len(sys.argv) == 3:
        solve(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"usage: {sys.argv[0]} HOST PORT | --test EXAMPLES_FILE", file=sys.stderr)
        raise SystemExit(2)
