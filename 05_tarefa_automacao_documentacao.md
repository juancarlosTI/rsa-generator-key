
### Projeto de Simulação PKI — Tarefa 5: Automação do pipeline e documentação

Objetivo
- Automatizar as tarefas 1–4 e consolidar documentação para reprodutibilidade.

Entregáveis esperados
- Scripts de automação (Makefile, npm scripts ou um CLI em Python/Node) para:
  - Gerar chaves (T1)
  - Gerar CSR (T2)
  - Criar AC e emitir certificados (T3)
  - Gerar/publicar CRL e simular OCSP (T4)
- Arquivo README detalhado com passos, pré-requisitos e troubleshooting.
- Pastas estruturadas com saídas organizadas e logs.

Arquitetura e diretórios sugeridos
```
pki-simulacao/
  ├─ scripts/
  │   ├─ gerar_chaves_rsa.py / gerar_chaves_rsa.js
  │   ├─ gerar_csr_rsa.py / gerar_csr_rsa.js
  │   ├─ emitir_certificado.py / emitir_certificado.js
  │   ├─ gerar_crl.py / gerar_crl.js
  │   └─ ocsp_mock.py / ocsp_mock.js
  ├─ keys/
  ├─ csrs/
  ├─ certs/
  ├─ ca/
  ├─ crl/
  └─ docs/
      └─ README.md
```

Passos detalhados (o que deve ser feito)
1) Definir variáveis de ambiente e configurações
   - Caminhos de entrada/saída, senhas, parâmetros de DN/SAN, políticas de uso.
   - Arquivo `.env` (sem versionar) e um `.env.example` com placeholders.

2) Criar um orquestrador simples
   - Opção A: Makefile com alvos (`make keys`, `make csr`, `make issue`, `make crl`, `make ocsp`).
   - Opção B: npm scripts no package.json (`npm run keys`, `npm run csr`, ...).
   - Opção C: CLI em Python/Node que chama cada etapa com flags.

3) Logging e idempotência
   - Gerar logs por etapa com timestamps.
   - Verificar existência de artefatos para evitar sobrescrever sem confirmação.
   - Versão/serial incremental para certificados e CRL.

4) Documentação
   - Criar docs/README.md com:
     - Visão geral PKI do projeto
     - Pré-requisitos (Python/Node, libs)
     - Como executar cada tarefa e automações
     - Estrutura de diretórios
     - Exemplos de comandos (OpenSSL para inspeção)
     - Segurança e boas práticas (proteção de chaves, backups, rotação)
     - Troubleshooting (erros comuns e soluções)

5) Qualidade e segurança
   - Validar saídas pós-execução (openssl verify, inspeção ASN.1 quando aplicável).
   - Garantir que chaves privadas não vazem (gitignore, permissões, sem logs sensíveis).
   - Opcional: adicionar testes automatizados mínimos (ex.: existência de arquivos, verificação de validade de certificados gerados).

Notas
- A automação pode ser incremental; priorize primeiro a execução ponta a ponta, depois refatore para robustez.
