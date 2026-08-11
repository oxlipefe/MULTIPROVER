#!/usr/bin/env python3
"""Generador del set diferencial `fixtures/diff/arithmetic/` (slice 2.9b-2).

El oráculo es revm: los fixtures NO declaran resultados esperados (hash/logs
van en cero, como todo `fixtures/diff/`). Lo que este generador tiene que
garantizar es que el bytecode EJERCITE de verdad el borde que dice ejercitar
— por eso cada caso deja su resultado en storage, donde el comparador de
post-state lo ve byte a byte.

Lecciones ya pagadas por slices anteriores y aplicadas acá:
 - gas de sobra en la tx (2.8d): `gasLimit` muy por encima del costo real, si
   no un fallo interno haltea la tx entera y los dos motores "coinciden".
 - `[SAME]` no es evidencia (2.6): cada caso guarda un valor OBSERVABLE.
"""
import json, os

MASK = (1 << 256) - 1
SENDER = "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
TARGET = "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
COINBASE = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

# --- opcodes que este slice agrega (más los que ya existían y se reusan) ---
OPS = {
    "DIV": 0x04, "SDIV": 0x05, "MOD": 0x06, "SMOD": 0x07,
    "ADDMOD": 0x08, "MULMOD": 0x09, "EXP": 0x0A, "SIGNEXTEND": 0x0B,
    "LT": 0x10, "GT": 0x11, "SLT": 0x12, "SGT": 0x13, "EQ": 0x14,
    "ISZERO": 0x15, "AND": 0x16, "OR": 0x17, "XOR": 0x18, "NOT": 0x19,
    "BYTE": 0x1A, "SHL": 0x1B, "SHR": 0x1C, "SAR": 0x1D,
    "MSTORE8": 0x53, "MCOPY": 0x5E, "MSTORE": 0x52, "MLOAD": 0x51,
    "SSTORE": 0x55, "POP": 0x50, "STOP": 0x00,
}

def neg(n):
    """-n en complemento a dos de 256 bits."""
    return (-n) & MASK

MIN_SIGNED = 1 << 255
MAX_SIGNED = MIN_SIGNED - 1
NEG1 = MASK

def push32(v):
    return "7f" + f"{v & MASK:064x}"

def push1(v):
    """PUSH1 con guarda. Un valor > 255 truncado a un byte corrompe el
    bytecode en silencio y el caso pasa a probar otra cosa — el bug exacto
    que 2.8c ya pago una vez, y que esta auditoria volvio a encontrar aca
    (`push1(0x200)` -> `0x00`, o sea que "MCOPY lee mas alla del final" leia
    del offset 0). Nunca mas sin assert."""
    assert 0 <= v <= 0xFF, f"push1({v:#x}) no entra en un byte: usa push32"
    return f"60{v:02x}"

def op(name):
    return f"{OPS[name]:02x}"

def sstore(slot, code):
    """`code` deja UN valor en el stack; lo guarda en `slot`."""
    return code + push1(slot) + op("SSTORE")

def binary(name, a, b):
    """`a OP b` — `a` es el tope, así que se pushea SEGUNDO."""
    return push32(b) + push32(a) + op(name)

def unary(name, a):
    return push32(a) + op(name)

def ternary(name, a, b, n):
    """ADDMOD/MULMOD: saca a, b, n en ese orden ⇒ se pushean al revés."""
    return push32(n) + push32(b) + push32(a) + op(name)

# ---------------------------------------------------------------- los casos

def case_division():
    """DIV/MOD/SDIV/SMOD: el cero y el borde MIN/-1."""
    parts, slot = [], 0
    for code in [
        binary("DIV", 8, 3),            # 2
        binary("DIV", 8, 0),            # 0 — NO es halt
        binary("DIV", 0, 8),            # 0
        binary("MOD", 8, 3),            # 2
        binary("MOD", 8, 0),            # 0
        binary("SDIV", neg(8), 3),      # -2
        binary("SDIV", 8, neg(3)),      # -2
        binary("SDIV", neg(8), neg(3)), # 2
        binary("SDIV", MIN_SIGNED, NEG1),  # MIN — el borde sin resultado válido
        binary("SDIV", 8, 0),           # 0
        binary("SMOD", neg(8), 3),      # -2 (signo del DIVIDENDO)
        binary("SMOD", 8, neg(3)),      # 2
        binary("SMOD", neg(8), neg(3)), # -2
        binary("SMOD", MIN_SIGNED, NEG1),  # 0
        binary("SMOD", 8, 0),           # 0
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_modular():
    """ADDMOD/MULMOD: el intermedio es de ANCHO COMPLETO, y N=0 da 0."""
    parts, slot = [], 0
    for code in [
        ternary("ADDMOD", 7, 3, 5),          # 0
        # (MAX+1) mod 3: ancho completo ⇒ 1. Con wrapping previo daría 0.
        ternary("ADDMOD", MASK, 1, 3),
        ternary("ADDMOD", MASK, MASK, 7),
        ternary("ADDMOD", 7, 3, 0),          # 0 — modulo cero
        ternary("MULMOD", 7, 3, 5),          # 1
        # MAX*2 mod 7: ancho completo ⇒ 2. Con wrapping previo daría 0.
        ternary("MULMOD", MASK, 2, 7),
        ternary("MULMOD", MASK, MASK, 11),
        ternary("MULMOD", 7, 3, 0),          # 0
        ternary("MULMOD", 0, MASK, 13),      # 0
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_exp():
    """EXP: gas por byte NO-CERO del exponente (EIP-160, 50/byte) + 0^0 = 1.

    Los exponentes crecen de 1 a 4 bytes a propósito: el gas_used total de la
    tx es lo que discrimina un `G_expbyte` mal. Sin exponentes de largos
    distintos, un 10 en vez de un 50 pasa desapercibido.
    """
    parts, slot = [], 0
    for code in [
        binary("EXP", 3, 4),           # 81, exponente de 1 byte
        binary("EXP", 0, 0),           # 1  — regla de la EVM
        binary("EXP", 0, 5),           # 0
        binary("EXP", 5, 0),           # 1, exponente de 0 bytes (solo la base)
        binary("EXP", 2, 300),         # 0 por wrapping, exponente de 2 bytes
        binary("EXP", 2, 255),         # 2^255, exponente de 1 byte
        binary("EXP", 7, 0x010000),    # exponente de 3 bytes
        binary("EXP", 3, 0x01000000),  # exponente de 4 bytes
        binary("EXP", MASK, 2),        # MAX^2 mod 2^256 = 1
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_comparison():
    """LT/GT/SLT/SGT/EQ/ISZERO — el cruce de la frontera de signo."""
    parts, slot = [], 0
    for code in [
        binary("LT", 1, 2),            # 1
        binary("LT", 2, 1),            # 0
        binary("LT", 1, 1),            # 0
        binary("GT", 2, 1),            # 1
        # SIN signo, -1 es el MÁXIMO; con signo es el mínimo. El par LT/SLT
        # sobre los MISMOS operandos es lo que separa las dos lecturas.
        binary("LT", NEG1, 1),         # 0
        binary("SLT", NEG1, 1),        # 1
        binary("GT", NEG1, 1),         # 1
        binary("SGT", NEG1, 1),        # 0
        binary("SLT", MIN_SIGNED, MAX_SIGNED),   # 1
        binary("SGT", MIN_SIGNED, MAX_SIGNED),   # 0
        binary("SLT", neg(8), neg(3)),  # 1
        binary("EQ", 7, 7),            # 1
        binary("EQ", 7, 8),            # 0
        unary("ISZERO", 0),            # 1
        unary("ISZERO", 7),            # 0
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_bitwise():
    """AND/OR/XOR/NOT/BYTE — y el índice de BYTE, que va al revés que ruint."""
    parts, slot = [], 0
    for code in [
        binary("AND", 0xF0F0, 0xFF00),
        binary("OR", 0xF0F0, 0x0F0F),
        binary("XOR", 0xFFFF, 0x0F0F),
        unary("NOT", 0),               # MAX
        unary("NOT", MASK),            # 0
        # BYTE cuenta desde el MÁS significativo: el byte 31 es el menos
        # significativo. Invertir el índice es la divergencia clásica acá.
        binary("BYTE", 31, 0xAABB),    # 0xBB
        binary("BYTE", 30, 0xAABB),    # 0xAA
        binary("BYTE", 0, 0xAABB),     # 0x00
        binary("BYTE", 0, MASK),       # 0xFF
        binary("BYTE", 32, MASK),      # 0 — fuera de rango, sin halt
        binary("BYTE", MASK, MASK),    # 0 — índice astronómico
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_shifts():
    """SHL/SHR/SAR (EIP-145): el desplazamiento va PRIMERO, y >= 256 satura.

    SAR satura en -1 para un negativo, no en 0 — el punto donde SAR y SHR
    dejan de ser el mismo opcode.
    """
    parts, slot = [], 0
    for code in [
        binary("SHL", 1, 1),           # 2   (shift=1, value=1)
        binary("SHL", 255, 1),         # MIN_SIGNED
        binary("SHL", 256, 1),         # 0  — satura
        binary("SHL", MASK, 1),        # 0  — shift astronómico
        binary("SHR", 1, 2),           # 1
        binary("SHR", 255, MIN_SIGNED),# 1
        binary("SHR", 256, MASK),      # 0
        binary("SHR", 1, MASK),        # MAX >> 1
        # SAR: acá se separa de SHR.
        binary("SAR", 1, MASK),        # MAX (-1 >> 1 = -1)
        binary("SAR", 255, MIN_SIGNED),# MAX (-2^255 >> 255 = -1)
        binary("SAR", 256, MASK),      # MAX — satura en -1, NO en 0
        binary("SAR", MASK, MASK),     # MAX — shift astronómico, negativo
        binary("SAR", 256, 8),         # 0   — positivo satura en 0
        binary("SAR", MASK, 8),        # 0
        binary("SAR", 1, 8),           # 4
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_signextend():
    parts, slot = [], 0
    for code in [
        binary("SIGNEXTEND", 0, 0xFF),      # MAX (-1 como int8)
        binary("SIGNEXTEND", 0, 0x7F),      # 0x7F
        binary("SIGNEXTEND", 0, 0xAB7F),    # 0x7F — descarta los bytes altos
        binary("SIGNEXTEND", 0, 0xABFF),    # MAX
        binary("SIGNEXTEND", 1, 0x80FF),    # extiende desde el byte 1
        binary("SIGNEXTEND", 1, 0x7FFF),    # 0x7FFF
        binary("SIGNEXTEND", 31, MASK),     # identidad
        binary("SIGNEXTEND", 32, 0xFF),     # identidad — sin halt
        binary("SIGNEXTEND", MASK, 0xFF),   # identidad — índice astronómico
    ]:
        parts.append(sstore(slot, code)); slot += 1
    return "".join(parts) + op("STOP")

def case_memory():
    """MSTORE8 y MCOPY (EIP-5656).

    MSTORE8 expande de a 1 byte, no de a 32: escribir en el offset 0 y leer
    con MLOAD prueba que solo cambió el byte alto de la palabra.
    MCOPY tiene que ser `memmove`: los dos solapes (hacia adelante y hacia
    atrás) dan resultados distintos si alguien lo implementa como `memcpy`.
    """
    code = ""
    # Patrón conocido en [0,32): 0x00112233...
    pattern = 0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
    code += push32(pattern) + push1(0) + op("MSTORE")
    # MSTORE8 en el offset 0: solo pisa el byte MÁS significativo de esa palabra.
    code += push32(0xAB) + push1(0) + op("MSTORE8")
    code += push1(0) + op("MLOAD") + push1(0) + op("SSTORE")
    # MSTORE8 con un valor > 1 byte: solo entra el menos significativo.
    code += push32(0x1234) + push1(1) + op("MSTORE8")
    code += push1(0) + op("MLOAD") + push1(1) + op("SSTORE")
    # MCOPY solapado HACIA ADELANTE: dest > src, rangos que se pisan.
    code += push1(16) + push1(0) + push1(8) + op("MCOPY")   # len,src,dest
    code += push1(0) + op("MLOAD") + push1(2) + op("SSTORE")
    code += push1(32) + op("MLOAD") + push1(3) + op("SSTORE")
    # MCOPY solapado HACIA ATRÁS: dest < src.
    code += push1(16) + push1(8) + push1(0) + op("MCOPY")
    code += push1(0) + op("MLOAD") + push1(4) + op("SSTORE")
    # MCOPY de largo cero: no toca ni expande, aunque los offsets sean absurdos.
    code += push32(0) + push32(MASK) + push32(MASK) + op("MCOPY")
    code += push1(0) + op("MLOAD") + push1(5) + op("SSTORE")
    # MCOPY que LEE más allá del final: expande (y se paga) y trae ceros.
    code += push1(32) + push32(0x200) + push32(0x100) + op("MCOPY")
    code += push32(0x100) + op("MLOAD") + push1(6) + op("SSTORE")
    # MSIZE al final, para que la expansión sea observable en el post-state.
    code += "59" + push1(7) + op("SSTORE")
    return code + op("STOP")


def case_mstore8_expansion():
    """MSTORE8 conduciendo SU PROPIA expansion de memoria.

    **Hueco de cobertura encontrado por mutation testing (M7), no por lectura.**
    En `case_memory` los MSTORE8 corren DESPUES de un MSTORE que ya expandio la
    memoria a 32 bytes, asi que expandir de a 1 o de a 32 daba exactamente lo
    mismo y la mutacion "MSTORE8 expande 32" pasaba 0/8.

    El offset 0x3F esta elegido para que las dos lecturas caigan en palabras
    DISTINTAS: 0x3F+1 = 64 = 2 palabras exactas, pero 0x3F+32 = 95 -> 96 = 3
    palabras. Con un offset alineado (0x40, por ejemplo) las dos redondean al
    mismo lugar y el caso no probaria nada.
    """
    code = ""
    code += push32(0xAB) + push1(0x3F) + op("MSTORE8")
    code += "59" + push1(0) + op("SSTORE")            # MSIZE: 64 vs 96
    code += push1(0x20) + op("MLOAD") + push1(1) + op("SSTORE")
    return code + op("STOP")

CASES = {
    "division_and_signed_division": (
        case_division(),
        "DIV/MOD/SDIV/SMOD. Dividir por cero da CERO, no halt (regla de la EVM). "
        "MIN/-1 = MIN es el unico par cuyo resultado con signo no existe, y la EVM "
        "lo define por wrapping. El signo de SMOD lo fija el DIVIDENDO, no el divisor.",
    ),
    "modular_arithmetic_full_width": (
        case_modular(),
        "ADDMOD/MULMOD con el intermedio de ANCHO COMPLETO. Los modulos estan elegidos "
        "para que las dos lecturas difieran: (MAX+1) mod 3 = 1 con ancho completo y 0 "
        "con wrapping previo; MAX*2 mod 7 = 2 vs 0. Con potencias de 2 el caso no "
        "probaria nada. Modulo cero da cero.",
    ),
    "exp_gas_scales_with_exponent_bytes": (
        case_exp(),
        "EXP: G_exp(10) + G_expbyte(50, EIP-160) por byte no-cero del exponente. Los "
        "exponentes van de 0 a 4 bytes A PROPOSITO: el gas_used total es lo que "
        "discrimina un G_expbyte mal (con un solo largo, un 10 en vez de un 50 pasa). "
        "0^0 = 1 y el desborde wrappea mod 2^256.",
    ),
    "comparison_across_the_sign_boundary": (
        case_comparison(),
        "LT/GT/SLT/SGT/EQ/ISZERO. Los pares LT/SLT y GT/SGT corren sobre los MISMOS "
        "operandos (-1 vs 1): sin signo -1 es el MAXIMO, con signo es el minimo. Un "
        "motor que confunda las dos lecturas diverge aca y en ningun otro lado.",
    ),
    "bitwise_and_byte_indexing": (
        case_bitwise(),
        "AND/OR/XOR/NOT/BYTE. BYTE cuenta desde el byte MAS significativo mientras "
        "ruint::byte() cuenta desde el menos: invertir la conversion es una divergencia "
        "que ningun tipo atrapa. Indice fuera de rango da 0, sin halt.",
    ),
    "shifts_saturate_past_the_word_width": (
        case_shifts(),
        "SHL/SHR/SAR (EIP-145). El DESPLAZAMIENTO es el primer operando, no el valor. "
        "Un desplazamiento >= 256 satura: 0 para los logicos, pero SAR satura en -1 "
        "para un valor negativo y en 0 para uno positivo — el punto exacto donde SAR "
        "deja de ser SHR.",
    ),
    "sign_extend_from_every_edge": (
        case_signextend(),
        "SIGNEXTEND: extiende desde el byte b y DESCARTA los bytes por encima. Con "
        "b >= 31 es la identidad, no un error.",
    ),
    "mstore8_drives_its_own_memory_expansion": (
        case_mstore8_expansion(),
        "MSTORE8 conduciendo SU PROPIA expansion. Hueco encontrado por mutation testing "
        "(M7): en el otro caso de memoria los MSTORE8 corrian despues de un MSTORE que ya "
        "habia expandido a 32 bytes, asi que expandir de a 1 o de a 32 era indistinguible. "
        "El offset 0x3F hace que las dos lecturas caigan en palabras distintas (64 vs 96), "
        "y MSIZE lo deja observable en storage.",
    ),
    "mstore8_and_mcopy_overlap": (
        case_memory(),
        "MSTORE8 expande de a 1 byte (no de a 32) y solo escribe el byte menos "
        "significativo de la palabra del stack. MCOPY (EIP-5656) es memmove, no memcpy: "
        "el set corre los DOS solapes (dest>src y dest<src), que dan resultados "
        "distintos si alguien copia byte a byte en el orden ingenuo. Largo cero no toca "
        "ni expande; leer mas alla del final expande y trae ceros. MSIZE al final deja "
        "la expansion observable en el post-state.",
    ),
}

def fixture(name, code, comment):
    return {
        "_comment": comment,
        "env": {
            "currentCoinbase": COINBASE,
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentGasLimit": "0x01c9c380",
            "currentBaseFee": "0x0a",
            "currentRandom": "0x" + "00" * 32,
            "currentExcessBlobGas": "0x00",
        },
        "config": {"chainid": "0x01"},
        "pre": {
            SENDER: {"nonce": "0x00", "balance": "0x3635c9adc5dea00000",
                     "code": "0x", "storage": {}},
            TARGET: {"nonce": "0x01", "balance": "0x00",
                     "code": "0x" + code, "storage": {}},
        },
        "transaction": {
            "sender": SENDER, "to": TARGET, "nonce": "0x00", "gasPrice": "0x0a",
            "data": ["0x"],
            # Gas MUY por encima del costo real (leccion de 2.8d): si el frame
            # muriera de OOG, los dos motores coincidirian en la nada.
            "gasLimit": ["0x0f4240"],
            "value": ["0x00"],
        },
        "post": {"Prague": [{
            "indexes": {"data": 0, "gas": 0, "value": 0},
            "hash": "0x" + "00" * 32,
            "logs": "0x" + "00" * 32,
        }]},
    }

out_dir = "cmd/conformance/fixtures/diff/arithmetic"
os.makedirs(out_dir, exist_ok=True)
groups = {
    "division.json": ["division_and_signed_division"],
    "modular.json": ["modular_arithmetic_full_width"],
    "exp.json": ["exp_gas_scales_with_exponent_bytes"],
    "comparison.json": ["comparison_across_the_sign_boundary"],
    "bitwise.json": ["bitwise_and_byte_indexing"],
    "shifts.json": ["shifts_saturate_past_the_word_width"],
    "signextend.json": ["sign_extend_from_every_edge"],
    "memory.json": ["mstore8_and_mcopy_overlap", "mstore8_drives_its_own_memory_expansion"],
}
for filename, names in groups.items():
    body = {n: fixture(n, *CASES[n]) for n in names}
    with open(os.path.join(out_dir, filename), "w") as f:
        json.dump(body, f, indent=2)
        f.write("\n")
    total = sum(len(CASES[n][0]) // 2 for n in names)
    print(f"{filename}: {len(names)} caso(s), {total} bytes de bytecode")
