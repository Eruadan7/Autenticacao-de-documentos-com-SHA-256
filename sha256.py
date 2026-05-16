import struct
import math

# --- Constantes do SHA-256 (primeiros 32 bits das partes fracionárias das raízes cúbicas dos primeiros 64 primos) ---
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# --- Valores iniciais do hash (primeiros 32 bits das partes fracionárias das raízes quadradas dos primeiros 8 primos) ---
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# --- Funções auxiliares lógicas ---
def rotr(x, n, bits=32):
    """Rotação à direita"""
    return (x >> n) | ((x & ((1 << n) - 1)) << (bits - n))

def shr(x, n):
    """Deslocamento à direita (sem rotação)"""
    return x >> n

def ch(x, y, z):
    """Escolha: se x bit = 1, escolhe y, senão z"""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Maioria: maioria entre bits de x, y, z"""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Σ₀ usado na compressão"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    """Σ₁ usado na compressão"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def delta0(x):
    """σ₀ usado na expansão da mensagem"""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def delta1(x):
    """σ₁ usado na expansão da mensagem"""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

# --- Etapa 1: Pré-processamento (padding + divisão em blocos) ---
def preprocess(message_bytes):
    """
    Recebe bytes da mensagem e retorna lista de blocos de 512 bits (64 bytes cada)
    Aplica padding: bit '1', zeros, e comprimento original em bits (64 bits)
    """
    # Comprimento original em bits (como inteiro de 64 bits, big-endian)
    original_bit_len = len(message_bytes) * 8
    # Padding: adiciona byte 0x80 (bit 1 seguido de 7 zeros)
    message_bytes += b'\x80'
    # Adiciona zeros até que o resto da divisão por 64 bytes (512 bits) seja 56 (pois sobram 8 bytes para o comprimento)
    while (len(message_bytes) % 64) != 56:
        message_bytes += b'\x00'
    # Adiciona o comprimento original em bits (big-endian, 8 bytes)
    message_bytes += struct.pack('>Q', original_bit_len)
    
    # Divide em blocos de 64 bytes (512 bits)
    blocks = []
    for i in range(0, len(message_bytes), 64):
        blocks.append(message_bytes[i:i+64])
    return blocks

# --- Etapa 2: Expansão da mensagem (cria schedule W[0..63] a partir de um bloco de 512 bits) ---
def expand_block(block_bytes):
    """
    Recebe 64 bytes do bloco e retorna lista de 64 palavras de 32 bits (W)
    """
    # Inicializa W com 64 posições
    W = [0] * 64
    # As primeiras 16 palavras são os 16 valores de 32 bits do bloco (big-endian)
    for i in range(16):
        W[i] = struct.unpack('>I', block_bytes[i*4:(i+1)*4])[0]
    # Expande as 48 palavras restantes usando σ₁ e σ₀
    for i in range(16, 64):
        s0 = delta0(W[i-15])
        s1 = delta1(W[i-2])
        W[i] = (W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF
    return W

# --- Etapa 3: Compressão de um bloco usando as funções e constantes ---
def compress_block(block_bytes, current_hash):
    """
    Processa um bloco de 512 bits e atualiza o hash corrente (8 palavras de 32 bits)
    """
    # Expande o bloco para o schedule W
    W = expand_block(block_bytes)
    
    # Inicializa as variáveis de trabalho a..h com o hash atual
    a, b, c, d, e, f, g, h = current_hash
    
    # Loop principal: 64 rodadas
    for t in range(64):
        T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    
    # Adiciona o resultado da compressão ao hash atual
    new_hash = [
        (current_hash[0] + a) & 0xFFFFFFFF,
        (current_hash[1] + b) & 0xFFFFFFFF,
        (current_hash[2] + c) & 0xFFFFFFFF,
        (current_hash[3] + d) & 0xFFFFFFFF,
        (current_hash[4] + e) & 0xFFFFFFFF,
        (current_hash[5] + f) & 0xFFFFFFFF,
        (current_hash[6] + g) & 0xFFFFFFFF,
        (current_hash[7] + h) & 0xFFFFFFFF
    ]
    return new_hash

# --- Função principal SHA-256 ---
def sha256(message_bytes):
    """
    Calcula o hash SHA-256 de uma mensagem em bytes.
    Retorna o hash como 32 bytes.
    """
    # Etapa 1: pré-processamento (padding + divisão em blocos)
    blocks = preprocess(message_bytes)
    
    # Inicializa o hash com os valores iniciais H0
    current_hash = H0.copy()
    
    # Etapa 2 e 3: para cada bloco, expande e comprime
    for block in blocks:
        current_hash = compress_block(block, current_hash)
    
    # Converte as 8 palavras de 32 bits para 32 bytes (big-endian)
    result = b''.join(struct.pack('>I', h) for h in current_hash)
    return result

"""# --- Exemplo de uso ---
if __name__ == "__main__":
    # Mensagem de teste
    msg = b"hello world"
    hash_bytes = sha256(msg)
    hash_hex = hash_bytes.hex()
    print(f"Mensagem: {msg.decode()}")
    print(f"SHA-256: {hash_hex}")
    
    # Verificação com hashlib (opcional)
    import hashlib
    expected = hashlib.sha256(msg).hexdigest()
    print(f"Esperado: {expected}")
    print("OK!" if hash_hex == expected else "Falha!")"""