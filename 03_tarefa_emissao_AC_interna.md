
### Projeto de Simulação PKI — Tarefa 3: Emissão simulada por AC interna (RSA)

Objetivo
- Criar uma Autoridade Certificadora (AC) interna simulada e usá-la para assinar um certificado X.509 a partir da CSR gerada na Tarefa 2.

Entregáveis esperados
- Certificado da AC raiz (ou intermediária) em PEM (ex.: `ca/ca_cert.pem`).
- Chave privada da AC em PEM protegida por senha (ex.: `ca/ca_key.pem`).
- Certificado emitido para o solicitante (ex.: `certs/server_exemplo_rsa.crt.pem`).
- Cadeia de certificados se houver intermediária (ex.: `certs/chain.pem`).
- Script(s) de emissão simulada (Python ou Node) e instruções de verificação com OpenSSL.

Escopo da simulação
- AC raiz local (self-signed) ou AC raiz + AC intermediária.
- Políticas simples: validade, usos de chave, extensões básicas.
- Sem requisitos legais (ICP-Brasil) — foco técnico/educacional.

Arquitetura e diretórios sugeridos
```
pki-simulacao/
  ├─ ca/
  │   ├─ ca_key.pem
  │   ├─ ca_cert.pem
  │   └─ serial.txt (controle de números de série)
  ├─ certs/
  │   ├─ server_exemplo_rsa.crt.pem
  │   └─ chain.pem (opcional)
  └─ csrs/
      └─ server_exemplo_rsa.csr.pem
```

Passos detalhados (o que deve ser feito)
1) Criar a AC interna
   - Gerar chave privada da AC (RSA 4096 recomendado para CA; protegida por senha e com forte controle de acesso).
   - Gerar certificado self-signed da AC (X.509) com as extensões:
     - BasicConstraints: CA:TRUE, pathLen (se quiser limitar hierarquia)
     - KeyUsage: keyCertSign, cRLSign
     - SubjectKeyIdentifier, AuthorityKeyIdentifier
     - Subject com DN adequado (CN=Exemplo CA, O=Exemplo LTDA, C=BR,...)
   - Armazenar arquivos em `ca/` e registrar um contador de série (`serial.txt`).

2) Carregar a CSR da Tarefa 2 e construir o certificado do solicitante
   - Ler `csrs/server_exemplo_rsa.csr.pem`.
   - Validar a CSR (assinatura e campos básicos).
   - Gerar número de série único (incremental, data-based, ou UUID convertido em inteiro).
   - Definir período de validade (ex.: 365 dias).
   - Definir o emissor (issuer) = DN da AC; subject = DN da CSR.
   - Copiar SAN da CSR e demais atributos necessários.

3) Definir extensões do certificado emitido
   - BasicConstraints: CA:FALSE
   - KeyUsage: digitalSignature, keyEncipherment (para TLS servidor); ajuste conforme uso pretendido.
   - ExtendedKeyUsage: serverAuth (1.3.6.1.5.5.7.3.1) e/ou clientAuth (1.3.6.1.5.5.7.3.2) conforme necessário.
   - SubjectAltName: copiar da CSR.
   - SubjectKeyIdentifier, AuthorityKeyIdentifier.

4) Assinar o certificado com a chave privada da AC
   - Algoritmo: SHA-256 com RSA.
   - Salvar o certificado emitido em `certs/server_exemplo_rsa.crt.pem`.
   - Opcional: gerar `chain.pem` concatenando certificados intermediários e raiz (se houver).

5) Verificações pós-emissão
   - Inspecionar o certificado:
     ````
     openssl x509 -in certs/server_exemplo_rsa.crt.pem -noout -text
     ````
   - Verificar cadeia (se tiver chain):
     ````
     openssl verify -CAfile ca/ca_cert.pem certs/server_exemplo_rsa.crt.pem
     ````

Critérios de segurança
- Proteger a chave privada da AC (idealmente HSM/Token em produção; aqui, senha forte e permissões restritas).
- Separar ambientes: geração de CA em host dedicado e offline (simulado aqui com diretório protegido).
- Controlar números de série e revogação (preparo para Tarefa 4).

Notas
- Você pode implementar esta tarefa tanto em Python (cryptography) quanto em Node (node-forge). O importante aqui é a descrição do que deve ser feito e os artefatos a produzir.
