import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import NodeRSA from 'node-rsa';
import { writeFile, readFile } from 'fs/promises'; // Importe readFile também!

// Cria a interface de leitura
const readLine = createInterface({ input, output });

async function showMenu() {
    console.log('\n=== Menu ===');
    console.log('1. Opção 1 - Gerar novas chaves RSA :');
    console.log('2. Opção 2 - Encriptar mensagem digitada: ');
    console.log('3. Opção 3 - Decriptar mensagem digitada');
    console.log('4. Opção 4 - Sair');
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

                    await writeFile('public_key.pem', publicKeyString);
                    await writeFile('private_key.pem', privateKeyString);
                    console.log(`Typeof - Private: ${typeof (privateKeyString)} -\nPublic: ${typeof (publicKeyString)}`);

                } else if (generateOption == 2) {
                    let pathToPrivateKey = await readLine.question('Endereço do arquivo chave_privada.pem: ');

                    const privateKeyContent = await readFile(pathToPrivateKey, { encoding: 'utf8' });
                    

                    key = new NodeRSA();
                    key.importKey(privateKeyContent,"private");

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
                if (key == 0){
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
            default:
                console.log('Opção inválida! Tente novamente.');
        }
    }

    readLine.close(); // Fecha a interface após sair do loop
}

main().catch((err) => console.error('Erro:', err));