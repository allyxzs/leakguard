# Revisão de credenciais — LeakGuard 1.0.2

Data: 25/11/2026. Base: `leakguard-v1.0.1-corrigido(1).zip`.

## Resultado

O pacote continha exemplos e testes com strings completas no formato de
credenciais de provedores. Elas estavam identificadas no projeto como dados de
teste/demonstração, mas seu formato era suficiente para ferramentas de segurança
sinalizarem possíveis vazamentos. A revisão não identificou uma credencial
operacional configurada no projeto. Isso **não comprova a validade ou invalidade
nos provedores**: nenhum valor encontrado foi usado para autenticar ou consultar
uma conta.

O Gitleaks 8.24.3, com suas regras padrão e sem exclusões adicionais, reportou
**8 achados antes e 0 depois**. Uma busca complementar por formatos específicos
localizou **16 ocorrências em 5 arquivos de texto** no pacote original, incluindo
amostras que o Gitleaks não reportou. Esses números são contagens de ferramentas,
não o número de contas ou credenciais reais comprometidas.

A origem informada dos alertas é **GitHub → Security → Secret scanning**.
Esse mecanismo é independente do LeakGuard e não obedece ao `.leakguardignore`
ou ao comentário `leakguard:allow`. A correção 1.0.1 tratava falsos positivos do
LeakGuard e SARIF, mas ainda distribuía as amostras completas.

## Escopo e achados por arquivo

Foram revisados todos os 31 arquivos do ZIP: código Go, regras, testes, exemplos,
documentação, workflows, Action, hook e configurações. As quatro imagens PNG
foram inspecionadas visualmente; os 127 quadros do GIF passaram por OCR e revisão
dos trechos relevantes. O SVG do banner também foi lido. Não foram identificados
valores completos de credenciais nas imagens: elas mostram prefixos mascarados.
As imagens foram preservadas e contextualizadas no README.

| Arquivo original | Achado | Alteração |
|---|---|---|
| `testdata/config.js` | Exemplos completos em formato AWS e GitHub | Referências a variáveis de ambiente |
| `testdata/demo.env` | Chave com formato Stripe Live e URL de banco contendo senha | Campos sensíveis vazios |
| `internal/scanner/scanner_test.go` | Amostras AWS, GitHub, Stripe, Google, Slack, cabeçalho de chave privada e senha em URL | Entradas sintéticas construídas em execução |
| `internal/gitscan/git_test.go` | Amostras AWS/GitHub e valores genéricos gravados como literais no teste | Amostras construídas durante o teste, em diretórios temporários |
| `README.md` | Exemplo no formato AWS, mesmo acompanhado de comentário de liberação | Placeholder sem formato de credencial |
| `internal/report/report_test.go` | Valor genérico fixo de teste | Amostra construída em execução e verificação adicional de mascaramento |
| `.leakguardignore` | Exclusões antigas de testes e demonstrações | Mantido; novo teste de higiene verifica esses arquivos independentemente das exclusões |
| `.gitignore` | Proteção limitada a `.env` | Acrescentados variantes locais e extensões comuns de arquivos de credenciais; templates continuam permitidos |

Não foi encontrado bloco de chave privada com material criptográfico: havia
somente um cabeçalho usado no teste. Mesmo esse cabeçalho literal completo foi
retirado do código de teste e passou a ser montado em memória.

## Como os testes continuam funcionando

`internal/testfixture` produz entradas determinísticas e claramente sintéticas,
com partes fixas e preenchimentos, somente quando os testes as solicitam. Não há
fragmentação ou codificação de uma credencial real. As amostras não são usadas
para autenticação e não há chamadas a provedores nos testes.

- Todas as **19 regras** têm um caso positivo, incluindo as que não eram
  exercitadas diretamente na suíte anterior.
- Testes de Git verificam a detecção de uma amostra já removida dos arquivos,
  mas ainda presente no histórico temporário do teste.
- Mensagens de falha foram ajustadas para não imprimir amostras completas.
- Texto, JSON e SARIF são verificados quanto ao mascaramento padrão.
- Um teste de higiene procura formatos completos de provedores nos arquivos de
  texto do projeto, inclusive testes e documentação, sem respeitar
  `.leakguardignore` nem `leakguard:allow`. A regra genérica de atribuições fica
  fora desse teste estático por também reconhecer código legítimo; os achados
  genéricos foram revisados separadamente e os exemplos têm teste próprio.
- Nenhuma regra de detecção de produção foi desativada ou relaxada nesta versão.

## Validação realizada

| Verificação local | Resultado |
|---|---|
| Gitleaks 8.24.3, diretório completo, regras padrão | 8 achados no original; 0 no corrigido |
| Busca complementar por formatos completos em arquivos | Ocorrências identificadas removidas/substituídas |
| `go vet ./...` | Aprovado |
| `go test -race -cover ./...`, Go 1.22.12, Linux | Aprovado |
| Compilação do CLI | Aprovada |
| `leakguard scan .` | 0 achados com a configuração do projeto |
| `leakguard scan testdata` | 0 achados; exemplos seguros |
| Etapa da Action com o CLI atualizado | Aprovada localmente |
| Relatório SARIF vazio contra o esquema oficial 2.1.0 | Válido |
| Exemplos nos formatos texto, JSON e SARIF | Aprovados |
| Imagens, GIF e metadados disponíveis | Sem credencial completa identificada |

Os resultados descrevem essas verificações, não uma garantia universal de que
qualquer ferramenta futura retornará zero alertas. Os testes automatizados não
cobrem integralmente todos os caminhos do CLI e do instalador de hooks.

## Limites observados no analisador

A revisão também encontrou comportamentos existentes que limitam a abrangência
da detecção. Eles não foram usados para ocultar os achados e permanecem como
pontos de melhoria além desta limpeza de credenciais:

- A varredura normal omite binários, caminhos ignorados e arquivos maiores que
  5 MiB. Não faz OCR de imagens; a inspeção visual/OCR acima foi externa ao CLI.
- Alguns erros de leitura são ignorados em `ScanPath`; erros do leitor de linhas
  não são propagados em `ScanContent`/`parseDiff`. Portanto, um resultado sem
  achados não prova que todo conteúdo pôde ser analisado.
- `history` usa `--no-merges`, examina linhas adicionadas e tem limite de tamanho
  de linha. Não é uma auditoria exaustiva de todos os objetos Git.
- A detecção depende de padrões e heurísticas; não consulta a validade de chaves
  e pode ter falsos positivos e falsos negativos.
- `--show-secrets` revela valores por opção explícita; não deve ser usado em logs
  públicos. `.gitignore` não retira arquivos que já estejam versionados.

## Atualizar e tratar os alertas do GitHub

1. Extraia o novo ZIP e substitua o conteúdo do projeto, incluindo arquivos
   ocultos. Preserve a pasta `.git` existente; não execute `git init` novamente.
2. Revise o diff, faça um commit e um push normais. Este pacote não altera o
   repositório remoto, não publica tags e não encerra alertas automaticamente.
3. Abra cada alerta em **Security → Secret scanning** e confira arquivo, linha,
   commit e validade. Os arquivos da tabela acima ajudam a identificar as
   amostras revisadas, mas não substituem a conferência do alerta.
4. **Somente quando confirmar que o valor é uma amostra fictícia**, use a opção
   adequada em **Close as**, como **Used in tests** ou **False positive**. Não
   classifique todos os alertas dessa forma indiscriminadamente.
5. Se alguma credencial for real, estiver ativa ou tiver origem desconhecida,
   revogue/rotacione no serviço de origem e atualize seus usos antes de resolver
   o alerta. A limpeza do código não revoga uma chave.

**Um commit novo não apaga os valores de commits antigos.** O GitHub examina o
histórico e não fecha automaticamente os alertas apenas porque o token foi
removido dos arquivos atuais. O ZIP não contém `.git`; por isso esta revisão
não verificou nem reescreveu branches, tags, forks, logs remotos ou o histórico
real do repositório. Se for necessário limpar esse histórico, isso exige uma
operação separada e coordenada com quem usa o repositório.

## Referências

- [GitHub: Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
- [GitHub: resolving alerts](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-secret-scanning-alerts/resolving-alerts)
- [Gitleaks 8.24.3](https://github.com/gitleaks/gitleaks/releases/tag/v8.24.3)
- [Esquema SARIF 2.1.0](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json)
