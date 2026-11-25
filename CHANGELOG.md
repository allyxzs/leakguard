# Changelog

## 1.0.2 — 25/11/2026

- Retiradas strings completas em formato de credenciais de provedores dos
  exemplos, README e testes. Exemplos usam variáveis de ambiente/campos vazios.
- Amostras sintéticas agora são construídas por `internal/testfixture` somente
  durante a execução dos testes, sem chamadas de autenticação.
- Cobertura positiva das 19 regras; teste de higiene de arquivos que não usa as
  exclusões normais; verificação de mascaramento em texto, JSON e SARIF.
- Mensagens de falha dos testes deixam de imprimir amostras completas.
- `.gitignore` ampliado para configurações locais e arquivos de credenciais.
- Gitleaks 8.24.3: 8 achados no ZIP de entrada e 0 na versão corrigida.
- `go vet`, testes com race detector, compilação, exemplos e etapa da Action
  validados localmente. Nenhuma regra de produção foi desativada.
- Análise completa, limitações e orientações para os alertas antigos em
  [SECURITY_REVIEW.md](SECURITY_REVIEW.md). O ZIP não apaga histórico Git nem
  fecha os alertas do Secret scanning.

## 1.0.1 — 24/11/2026

### Correções

- **Falsos positivos na própria base de código:** atribuições genéricas com
  chamadas de função ou acesso a índices sem aspas deixaram de ser tratadas como
  credenciais literais. Isso corrige os dois achados reproduzidos no ZIP original,
  em `internal/report/report.go` e `internal/scanner/scanner.go`, também ao
  analisar commits antigos. Valores entre aspas e regras específicas de tokens
  continuam sendo verificados. Nenhuma regra foi desativada e a lista de arquivos
  ignorados não foi ampliada.
- **SARIF vazio válido:** a lista `tool.driver.rules` agora é `[]` quando não
  há achados. Antes, era `null`, incompatível com o esquema SARIF 2.1.0.
- **Histórico Git:** somente cabeçalhos completos de commits são usados como
  separadores. A ocorrência do marcador interno dentro de um arquivo não altera
  mais a contagem nem a atribuição de achados ao commit.
- **GitHub Action:** os parâmetros são passados por variáveis de ambiente e
  validados. `fail-on-findings: false` permite achados, mas não oculta erros de
  execução nem falhas na geração do SARIF. O cache do setup-go foi desativado
  nesta Action porque o projeto não possui dependências externas nem `go.sum`.
- Versão do CLI atualizada para `1.0.1`.

### Validação

- `go vet ./...` e `go test -race ./...` executados com Go 1.22.12 no Linux.
- Testes de regressão para expressões de código, credenciais literais,
  credenciais removidas que permanecem no histórico, marcadores em arquivos,
  SARIF vazio, mascaramento e reutilização de regras.
- Varredura dos arquivos corrigidos e do histórico reconstruído a partir do
  ZIP original sem os dois falsos positivos.
- SARIF com e sem achados validado contra o esquema oficial SARIF 2.1.0.
- Oito cenários locais da etapa da Action: limpo, achados bloqueados, achados
  permitidos, SARIF desativado, modo inválido, booleano inválido, erro Git e erro
  ao gravar o relatório.
- CI passa a executar uma varredura do próprio projeto em sua matriz existente.

A execução remota do GitHub Actions não foi realizada nesta atualização.
O screenshot não contém o log detalhado do job; os problemas acima foram
reproduzidos e corrigidos localmente usando o ZIP fornecido.

### Como atualizar

1. Extraia o novo ZIP e copie o conteúdo da pasta `leakguard/` sobre o projeto
   existente, incluindo arquivos ocultos e a pasta `.github/`. Preserve a pasta
   `.git/` do seu repositório; este ZIP não inclui nem substitui seu histórico.
2. Revise as alterações, faça um commit e envie normalmente para o GitHub.
   O workflow local usa `uses: ./` e executará a versão corrigida após o push.
3. Confira a nova execução na aba **Actions**. Execuções antigas continuam
   mostrando o resultado que tiveram na época.

O novo analisador consegue examinar os commits antigos sem os falsos positivos
corrigidos; não é necessário apagar ou reescrever o histórico por esse motivo.
Se usar a versão por tag em outros repositórios, publique a tag correspondente
antes de referenciá-la; a entrega deste ZIP não publica tags no GitHub.
