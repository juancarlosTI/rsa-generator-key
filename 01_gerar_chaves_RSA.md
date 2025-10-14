
### Projeto de Simulação PKI — Tarefa 1: Gerar chaves (RSA apenas)

Este documento descreve e entrega a primeira tarefa do roteiro: geração de chaves assimétricas RSA usando Python.

#### Objetivo
- Gerar par de chaves RSA (privada + pública) com parâmetros seguros, salvar em arquivos PEM, com opção de proteção por senha.

#### Decisões e padrões
- Algoritmo: RSA 3072 bits (compatibilidade ampla; segurança robusta)
- Formatos:
  - Chave privada: PEM PKCS#8
  - Chave pública: PEM SubjectPublicKeyInfo
- Proteção de chave privada: PBKDF2 + AES-256-CBC (BestAvailableEncryption da biblioteca cryptography)

#### Pré-requisitos
- Python 3.10+
- Biblioteca cryptography

Instalação:
```
pip install cryptography
```

#### Estrutura de diretórios sugerida
```
pki-simulacao/
  ├─ keys/
  │   └─ rsa/
  └─ scripts/
      └─ gerar_chaves_rsa.py
```

#### Código Python (scripts/gerar_chaves_rsa.py)
```python
from pathlib import Path
from getpass import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Configurações
BASE_DIR = Path(__file__).resolve().parent.parent
RSA_DIR = BASE_DIR / "keys" / "rsa"
RSA_DIR.mkdir(parents=True, exist_ok=True)

# Definições de parâmetros
RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537

# Solicita senha para proteger a chave privada (opcional)
print("Opcional: defina uma senha para proteger a chave privada (Enter para deixar sem senha — não recomendado em produção).")
password = getpass("Senha (opcional): ")
if password:
    encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
else:
    encryption = serialization.NoEncryption()

# 1) Gerar chave RSA
rsa_private_key = rsa.generate_private_key(
    public_exponent=RSA_PUBLIC_EXPONENT,
    key_size=RSA_KEY_SIZE,
)
rsa_public_key = rsa_private_key.public_key()

# Serializar e salvar chave privada RSA (PKCS#8 PEM)
with open(RSA_DIR / "rsa_private_key.pem", "wb") as f:
    f.write(
        rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )

# Serializar e salvar chave pública RSA (PEM)
with open(RSA_DIR / "rsa_public_key.pem", "wb") as f:
    f.write(
        rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

print(f"Chaves RSA salvas em: {RSA_DIR}")
print("Concluído: chave RSA gerada.")
```

#### Como executar
1) Crie a estrutura de pastas e salve o script:
```
mkdir -p pki-simulacao/scripts pki-simulacao/keys/rsa
```
2) Salve o conteúdo acima em `pki-simulacao/scripts/gerar_chaves_rsa.py`.
3) Instale a dependência:
```
pip install cryptography
```
4) Execute:
```
python pki-simulacao/scripts/gerar_chaves_rsa.py
```
5) Informe uma senha (recomendado) ou pressione Enter para deixar sem senha.

#### Resultados esperados
Arquivos gerados:
- keys/rsa/rsa_private_key.pem
- keys/rsa/rsa_public_key.pem

#### Boas práticas de segurança
- Proteja a chave privada com senha forte e armazenamento seguro.
- Restrinja permissões do sistema de arquivos (ex.: chmod 600) para a chave privada.
- Em produção, prefira HSM/Token (A3) ou cofres de chaves (KMS) com controle de acesso e MFA.
- Faça backup seguro da chave privada, com rotação e política de destruição quando necessário.

#### Próximos passos
- [ ] Tarefa 2: Gerar CSR (PKCS#10) para a chave RSA
- [ ] Tarefa 3: Emissão simulada por AC interna (assinar certificado X.509)
- [ ] Tarefa 4: Publicação de CRL/OCSP "fake" e verificação de estado
- [ ] Tarefa 5: Automatizar pipeline e documentação
