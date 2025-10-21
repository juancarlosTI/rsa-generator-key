import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import NodeRSA from 'node-rsa';
import { writeFile, readFile } from 'fs/promises';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

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
    console.log('1. Opção 1 - Gerar CA - RAIZ:');
    console.log('2. Opção 2 - Gerar CA - INTERMEDIARIA:');
    console.log('3. Opção 3 - Gerar novas chaves RSA :');
    console.log('4. Opção 4 - Gerar CSR');
    console.log('5. Opção 5 - Assinar documento com certificado :');
    
    //console.log('2. Opção 2 - Encriptar mensagem digitada: ');
    //console.log('3. Opção 3 - Decriptar mensagem digitada');
    console.log('0. Opção 0 - Sair');
    
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
            case '1':
                console.log('Gerar novas chaves RSA / Utilizar chave privada existente :');
                let generateOption = await readLine.question('1- Gerar chave\n2- Carregar chave');
                if (generateOption == 1) {
                    
                    for (let i = 0; i < usuarios.length; i++) {
                        key = new NodeRSA({ b: 2048 });
                        let publicKeyString = key.exportKey('public');
                        let privateKeyString = key.exportKey('private');

                        await writeFile(`usuarios/${usuarios[i].nome}/public_key_${usuarios[i].nome}.pem`, publicKeyString);
                        await writeFile(`usuarios/${usuarios[i].nome}/private_key_${usuarios[i].nome}.pem`, privateKeyString);
                        console.log(`Typeof - Private: ${typeof (privateKeyString)} -\nPublic: ${typeof (publicKeyString)}`);
                    }


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
            case '200':
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
            case '300':
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
            case '2':
                for (let i = 0; i < usuarios.length; i++) {
                    try {
                        let pathToPrivateKey = await readLine.question(`Endereço do arquivo chave_privada.pem do :${usuarios[i].nome} `);
                        const privateKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });
                        
                        const CSR_DIR = path.join(`./usuarios/${usuarios[i].nome}`, `csr`);
                        if (!fs.existsSync(CSR_DIR)) fs.mkdirSync(CSR_DIR, { recursive: true });
                        
                        const DN = {
                            C: 'BR',
                            ST: 'Sao Paulo',
                            L: 'Sao Paulo',
                            O: 'Exemplo LTDA',
                            OU: 'TI',
                            CN: `${usuarios[i].nome}`, // Para servidor TLS use o FQDN
                        };

                        // SAN (Subject Alternative Name)
                        const SAN_DNS = [`${usuarios[i].nome}.exemplo.local`];
                        const SAN_EMAILS = [`${usuarios[i].email}`];
                        const SAN_CPF = [`${usuarios[i].CPF}`]

                        const { csrPem } = await generateCsrWithOpenSSL({
                            privateKeyContent,
                            DN,
                            SAN_DNS,
                            SAN_EMAILS,
                            cpf: usuarios[i].CPF,
                            outDir: CSR_DIR,
                            nome: usuarios[i].nome
                        });

                        // já grava no mesmo caminho que seu código original espera
                        await writeFile(`usuarios/${usuarios[i].nome}/csr/csr_key_${usuarios[i].nome}.csr.pem`, csrPem);
                        console.log(`CSR gerada com sucesso em: usuarios/${usuarios[i].nome}/csr/csr_key_${usuarios[i].nome}.csr.pem`);
                        } catch (err) {
                        console.error('Falha ao gerar CSR via OpenSSL:', err.message || err);
                        // se quiser abortar completamente:
                        // process.exit(1);
                        // ou continue para o próximo usuário
                        continue;
                        }    
                }

                break;
            case '3':
                // Gerar CA Raiz
                
            default:
                console.log('Opção inválida! Tente novamente.');
        }


    }

    readLine.close(); // Fecha a interface após sair do loop
}

main().catch((err) => console.error('Erro:', err));