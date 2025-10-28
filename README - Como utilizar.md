# Gerador e Verificador de Certificados e Assinaturas

Este projeto em Node.js permite criar uma hierarquia de CAs (Autoridades Certificadoras), emitir certificados para usuários, assinar documentos e verificar essas assinaturas.

## Como Usar (Passo a Passo)

### Pré-requisitos

*   **Node.js** instalado.
*   **OpenSSL** instalado e disponível no seu terminal (necessário para a verificação da cadeia de certificados).

### Iniciar o Programa

1.  Abra seu terminal na pasta do projeto.
2.  Execute o script:
    ```bash
    node index.js
    ```
    Você verá o menu principal.

---

### 1. Gerar CAs e Certificados de Usuários

Esta é a primeira etapa para configurar seu ambiente de certificados.

1.  No menu, digite `1` e pressione Enter.
    ```
    Digite a opção para navegar na aplicação: 1
    ```
2.  O script irá gerar automaticamente:
    *   A **CA Raiz** (em `ca-raiz/root/`)
    *   A **CA Intermediária** (em `ca-intermediaria/intermediate/`)
    *   **Certificados para usuários** (em `usuarios/<nome_do_usuario>/`)
3.  Aguarde a mensagem de "Processo concluído".

---

### 2. Assinar um Documento

Agora você pode usar a chave privada de um usuário para assinar uma mensagem.

1.  No menu, digite `2` e pressione Enter.
    ```
    Digite a opção para navegar na aplicação: 2
    ```
2.  **Caminho da Chave Privada:** Informe o caminho completo para a chave privada do usuário.
    *   Exemplo: `usuarios/joao/private_key_joao.pem`
3.  **Mensagem:** Digite a mensagem que você deseja assinar.
4.  O script irá:
    *   Calcular o hash da mensagem.
    *   Gerar uma assinatura digital.
    *   Salvar um arquivo `.assinatura.json` (ex: `documento_1701234567890.assinatura.json`) e um arquivo `.sig` na pasta raiz.

---

### 3. Verificar um Documento Assinado

Use esta opção para confirmar a autenticidade de um documento.

1.  No menu, digite `3` e pressione Enter.
    ```
    Digite a opção para navegar na aplicação: 3
    ```
2.  **Caminho do Arquivo `.assinatura.json`:** Informe o caminho completo para o arquivo JSON que você gerou na etapa anterior (ex.: `documento_1701234567890.assinatura.json`).
3.  O script irá:
    *   **Validar o Hash:** Verificar se o conteúdo do documento não foi alterado.
    *   **Validar a Assinatura:** Confirmar se a assinatura é autêntica usando a chave pública. (Se a chave pública não estiver no JSON, ele pedirá o caminho para o certificado/chave pública do assinante).
    *   **Validar a Cadeia de Certificação (Opcional):** Perguntará se você quer verificar a cadeia. Se sim, você precisará informar:
        *   O caminho para o **certificado do assinante** (ex: `usuarios/joao/joao.crt.pem`).
        *   O caminho para o **certificado da CA Raiz** (ex: `ca-raiz/root/rootCA.crt.pem`).
        *   (Opcional) O caminho para os **certificados intermediários** (ex: `ca-intermediaria/intermediate/intermediateCA.crt.pem`).

    O resultado final indicará se o documento e sua assinatura são válidos e se a cadeia de certificação é confiável.

---

### 4. Sair

1.  No menu, digite `4` e pressione Enter para sair do programa.

---

Pronto! Agora você pode usar o sistema para gerenciar seus certificados e garantir a autenticidade de seus documentos.
