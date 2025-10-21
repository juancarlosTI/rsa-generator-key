import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import NodeRSA from 'node-rsa';
import { writeFile, readFile } from 'fs/promises';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import crypto from 'crypto'

// CONFIGURAÇÕES
//const BASE_DIR = path.resolve(__dirname, '.');
//const KEYS_DIR = path.join(BASE_DIR, 'keys', 'rsa');
//const CSR_DIR = path.join(BASE_DIR, 'csrs');

// const usuarios = [
//     { nome: 'joao', email: 'joao@example.com', CPF: '123.456.666-00' },
//     { nome: 'maria', email: 'maria@example.com', CPF: '123.456.777-00' },
//     { nome: 'atacante', email: 'atacante@example.com', CPF: '123.456.888-00' }
// ]

// Cria a interface de leitura
const readLine = createInterface({ input, output });

async function showMenu() {
    console.log('\n=== Menu ===');
    
    //console.log('1. Opção 1 - Gerar novas chaves RSA');
    //console.log('2. Opção 2 - Gerar CSR');
    console.log('1. Opção 1 - Gerar CA - RAIZ, INTERMEDIARIA e gerar CERT dos usuarios');
    console.log('2. Opção 2 - Assinar documento com chave privada de um usuario');
    console.log('3. Opção 3 - Verificar documento assinado (case 5):');
    //console.log('2. Opção 2 - Encriptar mensagem digitada: ');
    //console.log('3. Opção 3 - Decriptar mensagem digitada');
    console.log('4. Opção 4 - Sair');
    
}

function buildSanExtension(dnsNames, emails, cpfs) {
    const altNames = [];
    for (const cpf of cpfs){
        altNames.push({ type: 3, value: cpf});
    }
    for (const d of dnsNames) {
        altNames.push({ type: 2, value: d }); // 2 = dNSName
    }
    for (const e of emails) {
        altNames.push({ type: 1, value: e }); // 1 = rfc822Name (email)
    }
    if (altNames.length === 0) return null;

    return {
        name: 'subjectAltName',
        altNames,
    };
}

function runOpenSSL(args, opts = {}) {
  try {
    return execFileSync('openssl', args, { stdio: 'inherit', ...opts });
  } catch (err) {
    // lançamos para o chamador tratar
    throw new Error(`OpenSSL failed (${args.join(' ')}): ${err.message || err}`);
  }
}

async function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Gera Root CA (key + self-signed cert)
async function generateRootCA({ outDir, subject }) {
  await ensureDir(outDir);
  const keyPath = path.join(outDir, 'rootCA.key.pem');
  const certPath = path.join(outDir, 'rootCA.crt.pem');
  const confPath = path.join(outDir, 'root_openssl.cnf');

  // OpenSSL config para a root CA
  const rootConf = `
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = ${subject.C}
ST = ${subject.ST}
L = ${subject.L}
O = ${subject.O}
OU = ${subject.OU}
CN = ${subject.CN}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
`;
  await writeFile(confPath, rootConf, { encoding: 'utf8' });

  // Gera chave RSA 4096
  runOpenSSL(['genrsa', '-out', keyPath, '4096']);

  // Gera certificado auto-assinado (root)
  runOpenSSL([
    'req', '-new', '-x509',
    '-days', '3650',
    '-key', keyPath,
    '-out', certPath,
    '-config', confPath,
    '-sha256'
  ]);

  return { keyPath, certPath, confPath };
}

// Gera Intermediate CA (key + csr) e assina com Root (gerando intermediate cert)
async function generateIntermediateCA({ outDir, subject, rootKeyPath, rootCertPath }) {
  await ensureDir(outDir);
  const keyPath = path.join(outDir, 'intermediate.key.pem');
  const csrPath = path.join(outDir, 'intermediate.csr.pem');
  const certPath = path.join(outDir, 'intermediateCA.crt.pem');

  const reqConfPath = path.join(outDir, 'intermediate_req.cnf');      // usado só para CSR
  const signConfPath = path.join(outDir, 'intermediate_sign.cnf');    // usado só para assinatura

  // Config para gerar CSR (sem authorityKeyIdentifier)
  const intReqConf = `
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_intermediate_req
prompt = no

[ req_distinguished_name ]
C = ${subject.C}
ST = ${subject.ST}
L = ${subject.L}
O = ${subject.O}
OU = ${subject.OU}
CN = ${subject.CN}

[ v3_intermediate_req ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
`;

  // Config para assinatura (autoridade conhecida — inclui authorityKeyIdentifier)
  const intSignConf = `
[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
`;

  await writeFile(reqConfPath, intReqConf, { encoding: 'utf8' });
  await writeFile(signConfPath, intSignConf, { encoding: 'utf8' });

  // Gera chave RSA 4096
  runOpenSSL(['genrsa', '-out', keyPath, '4096']);

  // Gera CSR usando reqConfPath (sem authorityKeyIdentifier)
  runOpenSSL([
    'req', '-new',
    '-key', keyPath,
    '-out', csrPath,
    '-config', reqConfPath,
    '-sha256'
  ]);

  // Assina CSR com Root CA — aqui usamos signConfPath (que contém authorityKeyIdentifier)
  runOpenSSL([
    'x509', '-req',
    '-in', csrPath,
    '-CA', rootCertPath,
    '-CAkey', rootKeyPath,
    '-CAcreateserial',
    '-out', certPath,
    '-days', '3650',
    '-sha256',
    '-extfile', signConfPath,
    '-extensions', 'v3_intermediate_ca'
  ]);

  return { keyPath, csrPath, certPath, reqConfPath, signConfPath };
}

// Gera chave, CSR e assina com a CA Intermediária para cada usuário
async function generateAndSignUserCerts({ usuarios, outRootDir, intermediateKey, intermediateCert }) {
  for (const u of usuarios) {
    const userDir = path.join(outRootDir, u.nome);
    await ensureDir(userDir);

    const keyPath = path.join(userDir, `${u.nome}.key.pem`);
    const csrPath = path.join(userDir, `${u.nome}.csr.pem`);
    const certPath = path.join(userDir, `${u.nome}.crt.pem`);
    const reqConfPath = path.join(userDir, `${u.nome}_req.cnf`);
    const signConfPath = path.join(userDir, `${u.nome}_sign.cnf`);

    // Gera chave do usuário (2048)
    runOpenSSL(['genrsa', '-out', keyPath, '2048']);

    // Config do CSR com subject (serialNumber = CPF) e subjectAltName (email / otherName)
    // Agora inclui emailAddress no distinguished_name para aparecer no subject
    const userReqConf = `
[ req ]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C = BR
ST = Sao Paulo
L = Sao Paulo
O = Exemplo LTDA
OU = TI
CN = ${u.nome}
emailAddress = ${u.email}
serialNumber = ${u.CPF}

[ v3_req ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = @alt_names

[ alt_names ]
email.1 = ${u.email}
# otherName format: OID;UTF8:<value>  --> OID usado: 1.2.3.4.5.6.7.8.1 (exemplo privado)
otherName.1 = 1.2.3.4.5.6.7.8.1;UTF8:${u.CPF}
`;

    // Config para assinatura do certificado do usuário (aplica authorityKeyIdentifier)
    // Inclui alt_names idem para gerar o certificado final com SAN correto
    const userSignConf = `
[ v3_user_cert ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ alt_names ]
email.1 = ${u.email}
otherName.1 = 1.2.3.4.5.6.7.8.1;UTF8:${u.CPF}
`;

    await writeFile(reqConfPath, userReqConf, { encoding: 'utf8' });
    await writeFile(signConfPath, userSignConf, { encoding: 'utf8' });

    // Gera CSR (o subject será preenchido a partir de reqConfPath)
    runOpenSSL([
      'req', '-new',
      '-key', keyPath,
      '-out', csrPath,
      '-config', reqConfPath,
      '-sha256'
    ]);

    // Assina CSR com a CA Intermediária, usando signConfPath (tem authorityKeyIdentifier)
    runOpenSSL([
      'x509', '-req',
      '-in', csrPath,
      '-CA', intermediateCert,
      '-CAkey', intermediateKey,
      '-CAcreateserial',
      '-out', certPath,
      '-days', '825',
      '-sha256',
      '-extfile', signConfPath,
      '-extensions', 'v3_user_cert'
    ]);

    console.log(`Certificado gerado para ${u.nome}: ${certPath}`);
  }
}

async function generateCsrWithOpenSSL({ privateKeyContent, DN, SAN_DNS = [], SAN_EMAILS = [], cpf, outDir, nome }) {
        // garante diretório
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    const privateKeyPath = path.join(outDir, `private_key_${nome}_from_openssl.pem`);
    await writeFile(privateKeyPath, privateKeyContent, { mode: 0o600 });

                    // Monta o subject. Mantemos serialNumber como CPF (conforme seu código original)
    const subj = `/C=${DN.C}/ST=${DN.ST}/L=${DN.L}/O=${DN.O}/OU=${DN.OU}/CN=${DN.CN}/serialNumber=${cpf}`;

                    // Monta altNames
    const altNamesLines = [];
    SAN_DNS.forEach((d, idx) => { altNamesLines.push(`DNS.${idx + 1} = ${d}`); });
    SAN_EMAILS.forEach((e, idx) => { altNamesLines.push(`email.${idx + 1} = ${e}`); });

    const opensslConfig = `
    [ req ]
    default_bits       = 2048
    prompt             = no
    distinguished_name = req_distinguished_name
    req_extensions     = v3_req

    [ req_distinguished_name ]
    C  = ${DN.C}
    ST = ${DN.ST}
    L  = ${DN.L}
    O  = ${DN.O}
    OU = ${DN.OU}
    CN = ${DN.CN}
    serialNumber = ${cpf}

    [ v3_req ]
    keyUsage = digitalSignature, keyEncipherment
    extendedKeyUsage = serverAuth, clientAuth
    subjectAltName = @alt_names

    [ alt_names ]
    ${altNamesLines.join('\n')}
    `;

    const confPath = path.join(outDir, `openssl_${nome}.cnf`);
    await writeFile(confPath, opensslConfig, { encoding: 'utf8' });

    const csrPath = path.join(outDir, `csr_key_${nome}.csr.pem`);

    try {
        execFileSync('openssl', [
        'req',
        '-new',
        '-key', privateKeyPath,
        '-out', csrPath,
        '-config', confPath,
        '-sha256',
        '-subj', subj
        ], { stdio: 'pipe' }); // pipe para podermos capturar erro se necessário

        const csrPem = await readFile(csrPath, { encoding: 'utf8' });
        return { csrPem, csrPath };
    } catch (err) {
        // retorna o erro para o chamador tratar (não faz process.exit aqui)
        throw new Error(`OpenSSL failed: ${err.message || err}`);
    } finally {
        // opcional: não removemos automaticamente a chave/conf; decisão sua
    }
}

// Função enxuta para verificar o documento gerado no case '5'
async function verifyDocumentFromCase5() {
  try {
    const filePath = await readLine.question('Caminho para o arquivo <documento>.<ts>.assinatura.json: ');
    const fp = filePath.trim();
    if (!fp || !fs.existsSync(fp)) {
      console.error('Arquivo não encontrado. Abortando.');
      return;
    }

    const raw = await readFile(fp, { encoding: 'utf8' });
    const obj = JSON.parse(raw);

    const { message, hashSHA256, signatureBase64, publicKeyPem } = obj;
    if (!message || !hashSHA256 || !signatureBase64) {
      console.error('Arquivo de assinatura incompleto (falta message/hash/signature).');
      return;
    }

    // 1) Verifica integridade do hash
    const recomputed = crypto.createHash('sha256').update(message, 'utf8').digest('hex');
    console.log('Hash armazenado:', hashSHA256);
    console.log('Hash recalculado:', recomputed);
    if (recomputed !== hashSHA256) {
      console.error('ERRO: integridade do documento falhou (hash diferente).');
      return;
    }
    console.log('Integridade do documento: OK');

    // 2) Verifica assinatura com chave pública
    let pubPem = publicKeyPem || null;
    if (!pubPem) {
      const pubPath = await readLine.question('Chave pública/Certificado do assinante (caminho .pem/.crt) [ENTER para abortar]: ');
      if (!pubPath || !fs.existsSync(pubPath.trim())) {
        console.error('Sem chave pública/certificado. Não é possível verificar a assinatura.');
        return;
      }
      const candidate = await readFile(pubPath.trim(), { encoding: 'utf8' });
      try {
        pubPem = crypto.createPublicKey(candidate).export({ type: 'spki', format: 'pem' });
      } catch (e) {
        console.error('Não foi possível extrair chave pública do arquivo fornecido:', e.message || e);
        return;
      }
    }

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(message, 'utf8');
    verifier.end();

    let signatureOk = false;
    try {
      signatureOk = verifier.verify(pubPem, signatureBase64, 'base64');
    } catch (err) {
      console.error('Erro ao verificar assinatura:', err.message || err);
      return;
    }
    console.log('Validade da assinatura (RSA-SHA256):', signatureOk ? 'OK' : 'FALHOU');
    if (!signatureOk) return;

    // 3) Verificação da cadeia de certificação (opcional; usa openssl)
    const wantChain = await readLine.question('Deseja verificar a cadeia de certificação até a CA Raiz? (s/N): ');
    if (wantChain.trim().toLowerCase() !== 's') return;

    // pede certificado do assinante, CA raiz e (opcional) intermediates
    const signerCertPath = await readLine.question('Caminho para o certificado PEM do assinante (assinante.crt): ');
    const rootCertPath = await readLine.question('Caminho para o certificado PEM da CA raiz (rootCA.crt): ');
    const intermediatesPath = await readLine.question('Caminho para intermediates concatenados (opcional, ENTER para pular): ');

    if (!signerCertPath || !rootCertPath || !fs.existsSync(signerCertPath.trim()) || !fs.existsSync(rootCertPath.trim())) {
      console.error('Certificados necessários não encontrados. Abortando verificação de cadeia.');
      return;
    }

    // Monta comando openssl verify
    const args = ['verify', '-CAfile', rootCertPath.trim()];
    if (intermediatesPath && intermediatesPath.trim()) args.push('-untrusted', intermediatesPath.trim());
    args.push(signerCertPath.trim());

    try {
      execFileSync('openssl', args, { stdio: 'pipe' });
      console.log('Validação da cadeia: OK (openssl verify retornou sucesso).');
    } catch (err) {
      const msg = (err && err.stderr) ? err.stderr.toString() : (err.message || String(err));
      console.error('Verificação da cadeia falhou (openssl verify):', msg);
    }

  } catch (err) {
    console.error('Erro durante verificação:', err.message || err);
  }
}

async function main() {

    
    const usuarios = [
        { nome: 'joao', email: 'joao@example.com', CPF: '123.456.666-00' },
        { nome: 'maria', email: 'maria@example.com', CPF: '123.456.777-00' },
        { nome: 'atacante', email: 'atacante@example.com', CPF: '123.456.888-00' }
    ]

    let running = true;
    let key = 0;
    while (running) {
        await showMenu(); // Exibe o menu
        const res = await readLine.question('Digite a opção para navegar na aplicação: ');
        
        

        switch (res) {
            case '1': {
                console.log('Gerando CA Raiz, CA Intermediária e emitindo certificados para usuários...');
                try {
                // Diretórios
                const ROOT_CA_DIR = path.join('.', 'ca-raiz', 'root');
                const INTER_CA_DIR = path.join('.', 'ca-intermediaria', 'intermediate');
                const USERS_DIR = path.join('.', 'usuarios');

                // 1) Root CA
                const rootSubject = {
                    C: 'BR',
                    ST: 'Sao Paulo',
                    L: 'Sao Paulo',
                    O: 'MinhaCorp',
                    OU: 'Infra',
                    CN: 'MinhaCorp Root CA'
                };
                console.log('--- Gerando Root CA ---');
                const root = await generateRootCA({ outDir: ROOT_CA_DIR, subject: rootSubject });
                console.log('Root CA criada:', root.certPath);

                // 2) Intermediate CA
                const interSubject = {
                    C: 'BR',
                    ST: 'Sao Paulo',
                    L: 'Sao Paulo',
                    O: 'MinhaCorp',
                    OU: 'Infra',
                    CN: 'MinhaCorp Intermediate CA'
                };
                console.log('--- Gerando Intermediate CA e assinando com Root ---');
                const inter = await generateIntermediateCA({
                    outDir: INTER_CA_DIR,
                    subject: interSubject,
                    rootKeyPath: root.keyPath,
                    rootCertPath: root.certPath
                });
                console.log('Intermediate CA criada:', inter.certPath);

                // 3) Emitir certificados para usuários com a CA Intermediária
                console.log('--- Emitindo certificados de usuários (assinados pela Intermediária) ---');
                await generateAndSignUserCerts({
                    usuarios,
                    outRootDir: USERS_DIR,
                    intermediateKey: inter.keyPath,
                    intermediateCert: inter.certPath
                });

                console.log('Processo concluído. Verifique os diretórios ca/root, ca/intermediate e usuarios/*');
                } catch (err) {
                console.error('Erro durante geração das CAs/Certificados:', err.message || err);
                }
                break;
            }
            case '4':
                console.log("Saindo!");
                running = false;
                break;
            case '2':
                // Assinar arquivos com a chave de um usuario válida
                let pathToPrivateKey = await readLine.question(`Endereço do arquivo chave_privada.pem :`);
                const privateKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });
                
                // Mensagem para ser encriptada
                let messageToEncript = await readLine.question(`Digite uma mensagem para ser encriptada: `)
                // Gerar hash
                const hashMessage = crypto.createHash('sha256').update(messageToEncript, 'utf8').digest('hex');
                console.log('Hash (SHA-256):', hashMessage);
                const signer = crypto.createSign('RSA-SHA256');
                signer.update(messageToEncript, 'utf8');
                signer.end();


                let signatureBase64;
                try {
                    signatureBase64 = signer.sign(privateKeyContent, 'base64');
                    } catch (err) {
                    console.error('Falha ao assinar com a chave privada:', err.message || err);
                    // trate o erro conforme necessário (continue/abort)
                    break;
                    }

                console.log('Assinatura (Base64) gerada.');

                // Public pem
                let publicPem = null;
                try {
                    publicPem = crypto.createPublicKey(privateKeyContent).export({ type: 'spki', format: 'pem' });
                } catch (err) {
                    console.warn('Não foi possível derivar chave pública da chave privada:', err.message || err);
                }

                // Monta documento legível / verificável
                const ts = Date.now();
                const outName = `documento_${ts}`;
                const signedDoc = {
                    metadata: { createdAt: new Date().toISOString(), sourceKeyPath: pathToPrivateKey },
                    message: messageToEncript,
                    hashSHA256: hashMessage,
                    signatureBase64,
                    publicPem // pode ser null, então o verificador perguntará pela chave
                };

                const outJsonPath = path.join('.', `${outName}.assinatura.json`);
                const outSigPath = path.join('.', `${outName}.assinatura.sig`);

                await writeFile(outJsonPath, JSON.stringify(signedDoc, null, 2), { encoding: 'utf8', mode: 0o600 });
                await writeFile(outSigPath, signatureBase64, { encoding: 'utf8', mode: 0o600 });

                console.log(`Documento assinado salvo em: ${outJsonPath}`);
                console.log(`Assinatura pura salva em: ${outSigPath}`);

                // Verificação
                try {
                    // Ler a chave publica exportada
                    //let pathToPublicKey = await readLine.question(`Endereço do arquivo chave_publica.pem :`);
                    //const publicKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });

                    //const publicKey = crypto.createPublicKey(privateKeyContent).export({ type: 'spki', format: 'pem' });
                    const verifier = crypto.createVerify('RSA-SHA256');
                    verifier.update(messageToEncript, 'utf8');
                    verifier.end();
                    const ok = verifier.verify(publicPem, signatureBase64, 'base64');
                    console.log('Verificação local da assinatura:', ok ? ok : 'FALHOU');
                    } catch (err) {
                    console.warn('Verificação local não pôde ser executada (debug):', err.message || err);
                    }
                break;
            case '3':
                await verifyDocumentFromCase5();
                break;

            default:
                console.log('Opção inválida! Tente novamente.');
        }


    }

    readLine.close(); // Fecha a interface após sair do loop
}

main().catch((err) => console.error('Erro:', err));