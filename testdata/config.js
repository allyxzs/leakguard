// Exemplo seguro: configure credenciais fora do código-fonte.
// Os testes geram amostras sintéticas somente em memória/diretórios temporários.
const aws = { accessKeyId: process.env.AWS_ACCESS_KEY_ID };
const gh = process.env.GITHUB_TOKEN;
const ok = process.env.API_KEY;
