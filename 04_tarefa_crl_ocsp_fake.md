
### Projeto de Simulação PKI — Tarefa 4: Publicação de CRL/OCSP "fake" e verificação de estado

Objetivo
- Simular publicação de estado de revogação para certificados emitidos na Tarefa 3, via:
  - CRL (Certificate Revocation List)
  - OCSP (Online Certificate Status Protocol)

Entregáveis esperados
- Arquivo CRL da AC (ex.: `crl/ca_crl.pem`) contendo pelo menos um certificado revogado.
- Script(s) para gerar e atualizar CRL (Python/Node) com número de versão (CRL Number), thisUpdate/nextUpdate.
- Servidor/endpoint de OCSP simulado (pode ser um mock HTTP local) que responda "good"/"revoked" para um serial informado.
- Instruções para validação com OpenSSL (consulta a CRL e OCSP).

Arquitetura e diretórios sugeridos
```
pki-simulacao/
  ├─ ca/
  │   ├─ ca_key.pem
  │   └─ ca_cert.pem
  ├─ certs/
  │   └─ server_exemplo_rsa.crt.pem
  ├─ crl/
  │   └─ ca_crl.pem
  └─ ocsp/
      └─ mock_ocsp.json (ou servidor simples)
```

Passos detalhados (o que deve ser feito)
1) Planejar revogação
   - Escolher um certificado emitido (pela Tarefa 3) e marcar seu número de série para revogação.
   - Definir motivo de revogação (ex.: keyCompromise) e data de revogação.

2) Gerar e publicar CRL
   - Criar uma CRL assinada pela AC, incluindo os números de série revogados e respectivos motivos/datas.
   - Definir campos: thisUpdate, nextUpdate, CRL Number, Authority Key Identifier.
   - Publicar em `crl/ca_crl.pem`.

3) Simular OCSP
   - Implementar um mock simples que, dado um serial e o emissor, retorna status:
     - good | revoked | unknown
   - O mock pode ser:
     - Um arquivo JSON com o mapa serial → status.
     - Um servidor HTTP local que lê esse mapa e responde (ex.: Express em Node ou Flask em Python).
   - Assinatura de respostas OCSP reais é complexa; para simulação, foque no fluxo e nos campos principais.

4) Validar verificação de estado
   - Usar OpenSSL para checar CRL:
     ````
     openssl verify -CAfile ca/ca_cert.pem -crl_check -CRLfile crl/ca_crl.pem certs/server_exemplo_rsa.crt.pem
     ````
   - Simular consulta OCSP:
     - Exemplo: um script que consulta o mock e imprime o status conforme o serial do certificado.

Boas práticas
- Atualizar CRL periodicamente (nextUpdate) e versionar (CRL Number).
- Garantir integridade (assinatura pela AC) mesmo na simulação.
- Manter log/registro das revogações e motivos.

Notas
- Em produção, OCSP envolve responder com estrutura ASN.1 assinada e tempo de validade; aqui a meta é didática.
