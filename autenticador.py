from sha256 import sha256
import sys

def gerar_chave(nome_arquivo):
    with open(nome_arquivo, 'rb') as f:
        dados = f.read()
    chave = sha256(dados)
    
    with open(f"{nome_arquivo}.chave", "wb") as f:
        f.write(chave)

def autenticar(nome_chave, nome_arquivo):
    with open(nome_chave, 'rb') as f:
        chave_original = f.read()

    with open(nome_arquivo, 'rb') as f:
        dados = f.read()
    nova_chave = sha256(dados)

    if chave_original == nova_chave:
        print("O arquivo inserido é legítimo")
    else:
        print("O arquivo inserido não é original")
    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python autenticador.py gerar_chave <arquivo>")
        print("Uso: python autenticador.py autenticar <chave> <arquivo>")
        sys.exit(1)

    if sys.argv[1] == "gerar_chave":
        gerar_chave(sys.argv[2])

    if sys.argv[1] == "autenticar":
        autenticar(sys.argv[2], sys.argv[3])