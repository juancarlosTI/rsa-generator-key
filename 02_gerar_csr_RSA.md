
### Projeto de Simulação PKI — Tarefa 2: Gerar CSR (RSA)

Esta tarefa cria uma CSR (Certificate Signing Request, PKCS#10) usando a chave RSA gerada na Tarefa 1.

#### Objetivo
- Gerar um arquivo .csr contendo:
  - Chave pública correspondente à chave privada RSA
  - Distinguished Name (DN) do solicitante
  - Extensões relevantes (SAN para DNS e/ou email)
  - Prova de posse da chave (assinatura da CSR)

#### Pré-requisitos
- Conclusão da Tarefa 1 (chaves em keys/rsa/)
- Python 3.10+
- Biblioteca cryptography

#### Campos do DN sugeridos
- Country Name (C): BR
- State or Province (ST): <Estado>
- Locality (L): <Cidade>
- Organization (O): <Organização>
- Organizational Unit (OU): <Unidade>
- Common Name (CN): <FQDN ou Nome do titular>

#### Código Python (scripts/gerar_csr_rsa.py)
```python
from pathlib import Path
from getpass import getpass
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

# Configurações
BASE_DIR = Path(__file__).resolve().parent.parent
RSA_DIR = BASE_DIR / "keys" / "rsa"
CSR_DIR = BASE_DIR / "csrs"
CSR_DIR.mkdir(parents=True, exist_ok=True)

# Parâmetros do DN e SAN — edite conforme seu caso
C = "BR"
ST = "Sao Paulo"
L = "Sao Paulo"
O = "Exemplo LTDA"
OU = "TI"
CN = "server.exemplo.local"   # Para certificados de servidor, use o FQDN
SAN_DNS = ["server.exemplo.local", "www.exemplo.local"]
SAN_EMAILS = []  # ex: ["admin@exemplo.local"]

# Carregar chave privada RSA
key_path = RSA_DIR / "rsa_private_key.pem"
print(f"Carregando chave privada: {key_path}")
password = getpass("Senha da chave (se houver, Enter se não): ")
if password == "":
    password = None

with open(key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=password.encode('utf-8') if password else None)

# Construir o sujeito (DN)
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, C),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST),
    x509.NameAttribute(NameOID.LOCALITY_NAME, L),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
    x509.NameAttribute(NameOID.COMMON_NAME, CN),
])

# Criar SANs (opcional, mas recomendado para TLS)
alt_names = []
for dns in SAN_DNS:
    alt_names.append(x509.DNSName(dns))
for email in SAN_EMAILS:
    alt_names.append(x509.RFC822Name(email))

# Montar CSR
csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
if alt_names:
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(alt_names), critical=False
    )

csr = csr_builder.sign(private_key, hashes.SHA256())

# Salvar CSR em PEM
csr_path = CSR_DIR / "server_exemplo_rsa.csr.pem"
with open(csr_path, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

print(f"CSR gerada em: {csr_path}")
```

#### Como executar
1) Salve o script em `pki-simulacao/scripts/gerar_csr_rsa.py`.
2) Ajuste os campos DN e SAN no topo do script conforme seu contexto.
3) Execute:
```
python pki-simulacao/scripts/gerar_csr_rsa.py
```
4) Se a chave privada estiver protegida, informe a senha.

#### Resultado esperado
- Arquivo: `csrs/server_exemplo_rsa.csr.pem`
- Inspeção com OpenSSL (opcional):
```
openssl req -in csrs/server_exemplo_rsa.csr.pem -noout -text
```

#### Próximos passos
- [ ] Tarefa 3: Criar AC interna e emitir certificado X.509 a partir da CSR
- [ ] Tarefa 4: Publicar CRL/OCSP fake e testar verificação
- [ ] Tarefa 5: Automatizar pipeline e documentação
