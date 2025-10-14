import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import NodeRSA from 'node-rsa';
import { writeFile, readFile } from 'fs/promises';
import fs from 'fs';
import path from 'path';
import forge from 'node-forge';

// CONFIGURAÇÕES
//const BASE_DIR = path.resolve(__dirname, '.');
//const KEYS_DIR = path.join(BASE_DIR, 'keys', 'rsa');
//const CSR_DIR = path.join(BASE_DIR, 'csrs');

// Cria a interface de leitura
const readLine = createInterface({ input, output });

async function showMenu() {
    console.log('\n=== Menu ===');
    console.log('1. Opção 1 - Gerar novas chaves RSA :');
    console.log('2. Opção 2 - Encriptar mensagem digitada: ');
    console.log('3. Opção 3 - Decriptar mensagem digitada');
    console.log('4. Opção 4 - Sair');
    console.log('5. Opção 5 - Gerar CSR')
}

function buildSanExtension(dnsNames, emails) {
    const altNames = [];
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

async function main() {
    let running = true;
    let key = 0;
    while (running) {
        await showMenu(); // Exibe o menu
        const res = await readLine.question('Digite a opção para navegar na aplicação: ');

        switch (res) {
            case '1':
                console.log('Gerar novas chaves RSA / Utilizar chave privada existente :');
                let generateOption = await readLine.question('1- Gerar chave\n2- Carregar chave');
                if (generateOption == 1) {
                    key = new NodeRSA({ b: 2048 });
                    let publicKeyString = key.exportKey('public');
                    let privateKeyString = key.exportKey('private');

                    await writeFile('keys/public_key.pem', publicKeyString);
                    await writeFile('keys/private_key.pem', privateKeyString);
                    console.log(`Typeof - Private: ${typeof (privateKeyString)} -\nPublic: ${typeof (publicKeyString)}`);

                } else if (generateOption == 2) {
                    let pathToPrivateKey = await readLine.question('Endereço do arquivo chave_privada.pem: ');

                    const privateKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });


                    key = new NodeRSA();
                    key.importKey(privateKeyContent, "private");

                    console.log('Chave privada carregada com sucesso!');

                }

                //console.log("key: ", key);
                // Salvar public/private key em um arquivo
                break;
            case '2':
                console.log('Encriptar mensagem digitada');
                if (key != 0) {
                    // Encriptar
                    const inputParaEncriptar = await readLine.question('Digite a mensagem para criptografar: ');
                    const mensagemEncriptada = key.encrypt(inputParaEncriptar, 'base64');
                    console.log('Mensagem criptografada (Base64):', mensagemEncriptada);
                    await writeFile('mensagem_criptografada.txt', mensagemEncriptada);
                } else {
                    console.log('Erro: Nenhuma chave RSA gerada. Por favor, gere uma chave (Opção 1) primeiro.');
                }

                break;
            case '3':
                console.log('Decriptar mensagem digitada');
                if (key == 0) {
                    console.log("'Erro: Nenhuma chave RSA gerada. Por favor, gere uma chave (Opção 1) primeiro.'");
                    break;
                }
                const pathToMessageEncripted = await readLine.question('Endereço da mensagem criptografada: ');
                const messageContent = await readFile(pathToMessageEncripted, { encoding: 'utf8' });
                const mensagemDecriptada = key.decrypt(messageContent, 'utf8');

                console.log('\nMensagem descriptografada:', mensagemDecriptada);


                break;
            case '4':
                console.log("Saindo!");
                running = false;
                break;
            case '5':
                console.log("")

                // Ler chave privada
                let pathToPrivateKey = await readLine.question('Endereço do arquivo chave_privada.pem: ');
                const privateKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });
                
                // Forge
                const loadPrivateKey = forge.pki.privateKeyFromPem(privateKeyContent);

                if (!loadPrivateKey){
                    console.log("Erro com a chave privada");
                }

                // console.log("PrivateKey (Forge): ", loadPrivateKey);

                const CSR_DIR = path.join('./', 'csr');
                if (!fs.existsSync(CSR_DIR)) fs.mkdirSync(CSR_DIR, { recursive: true });

                console.log("Exists: ", fs.existsSync(CSR_DIR));
                // #### Campos do DN sugeridos
                //- Country Name (C): BR
                //- State or Province (ST): <Estado>
                //- Locality (L): <Cidade>
                //- Organization (O): <Organização>
                //- Organizational Unit (OU): <Unidade>
                //- Common Name (CN): <FQDN ou Nome do titular></FQDN>
                const DN = {
                    C: 'BR',
                    ST: 'Sao Paulo',
                    L: 'Sao Paulo',
                    O: 'Exemplo LTDA',
                    OU: 'TI',
                    CN: 'Juan Carlos', // Para servidor TLS use o FQDN
                };

                // SAN (Subject Alternative Name)
                const SAN_DNS = ['server.exemplo.local'];
                const SAN_EMAILS = ['admin@dominio.local'];

                const map = {
                    C: 'C',
                    ST: 'ST',
                    L: 'L',
                    O: 'O',
                    OU: 'OU',
                    CN: 'CN',
                };
                const attrs = [];
                Object.keys(map).forEach((k) => {
                    if (DN[k]) {
                        attrs.push({ shortName: map[k], value: DN[k] });
                    }
                });

                // 2) Criar CSR
                const csr = forge.pki.createCertificationRequest();

                // Subject
                csr.setSubject(attrs);

                // Public key derivada da private key
                csr.publicKey = forge.pki.rsa.setPublicKey(loadPrivateKey.n, loadPrivateKey.e);

                console.log("Publickey (Forge): ", csr.publicKey);

                const sanExt = buildSanExtension(SAN_DNS, SAN_EMAILS);
                if (sanExt) {
                    csr.setAttributes([
                    {
                        name: 'extensionRequest',
                        extensions: [sanExt],
                    },
                    ]);
                }

                // 3) Assinar CSR com SHA-256
                csr.sign(loadPrivateKey, forge.md.sha256.create());

                // 4) Validar CSR localmente
                const valid = csr.verify();
                if (!valid) {
                    console.error('Falha na verificação local da CSR.');
                    process.exit(1);
                }

                const csrPem = forge.pki.certificationRequestToPem(csr);
                const csrPath = path.join(CSR_DIR, 'server_exemplo_rsa.csr.pem');

                await writeFile('csr/csr_key.csr.pem', csrPem);

                console.log('CSR gerada com sucesso em: csr/csr_key.csr.pem');
                break;
            default:
                console.log('Opção inválida! Tente novamente.');
        }


    }

    readLine.close(); // Fecha a interface após sair do loop
}

main().catch((err) => console.error('Erro:', err));