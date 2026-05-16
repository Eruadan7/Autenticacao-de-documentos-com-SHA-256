# Autenticador de Arquivos via SHA-256

Ferramenta de linha de comando para verificar a integridade de arquivos. Gera uma assinatura criptográfica (hash SHA-256) de um arquivo e, posteriormente, permite confirmar se o arquivo foi alterado.

## Como funciona

O SHA-256 é uma função de hash: transforma qualquer conteúdo em uma sequência de 32 bytes determinística e única. O mesmo arquivo sempre produz o mesmo hash; qualquer alteração — mesmo de um único bit — produz um hash completamente diferente. Isso permite detectar modificações sem precisar comparar os arquivos diretamente.

O fluxo tem duas etapas:

1. **Gerar a chave** — calcula o hash do arquivo original e salva em um arquivo `.chave`.
2. **Autenticar** — recalcula o hash do arquivo em questão e compara com a chave salva.

## Requisitos

- Python 3.6 ou superior
- Nenhuma dependência externa — a implementação do SHA-256 (`sha256.py`) está inclusa no projeto

## Instalação

Basta ter os dois arquivos no mesmo diretório:

```
sha256.py
autenticador.py
```

## Uso

### 1. Gerar a chave de um arquivo

```bash
python autenticador.py gerar_chave <arquivo>
```

Isso cria um arquivo `<arquivo>.chave` no mesmo diretório. Guarde essa chave em local seguro — ela é a referência de autenticidade.

**Exemplo:**

```bash
python autenticador.py gerar_chave contrato.pdf
# Gera: contrato.pdf.chave
```

### 2. Autenticar um arquivo

```bash
python autenticador.py autenticar <chave> <arquivo>
```

Compara o hash do arquivo com o hash registrado na chave. Imprime o resultado na saída padrão.

**Exemplo:**

```bash
python autenticador.py autenticar contrato.pdf.chave contrato.pdf
# O arquivo inserido é legítimo

python autenticador.py autenticar contrato.pdf.chave contrato_modificado.pdf
# O arquivo inserido não é original
```

## Observações

A chave gerada é um arquivo binário de 32 bytes — não é legível como texto. Ela deve ser tratada como um artefato de referência: se a chave for adulterada junto com o arquivo, a verificação perde o sentido. Para casos que exigem garantia mais forte de custódia da chave, considere armazená-la em um sistema separado ou assinar a chave com uma chave privada.

A implementação do SHA-256 em `sha256.py` é didática e segue o padrão FIPS 180-4. Para uso em produção com grandes volumes de dados, considere substituir pela implementação nativa do Python via `hashlib.sha256`.
