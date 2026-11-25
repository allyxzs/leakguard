// Command leakguard detects secrets before they leak.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/allyxzs/leakguard/internal/gitscan"
	"github.com/allyxzs/leakguard/internal/hook"
	"github.com/allyxzs/leakguard/internal/report"
	"github.com/allyxzs/leakguard/internal/scanner"
)

var version = "1.0.2"

const usage = `🛡  LeakGuard — detector de segredos em projetos

Uso:
  leakguard <comando> [opções]

Comandos:
  scan [caminho]       Varre arquivos de um diretório (padrão: .)
  env  [caminho]       Analisa apenas arquivos .env
  staged               Varre as mudanças em stage (usado no pre-commit)
  history              Varre todo o histórico Git
  install-hook         Instala o hook pre-commit que bloqueia commits com segredos
  uninstall-hook       Remove o hook pre-commit
  rules                Lista as regras de detecção
  version              Mostra a versão

Opções comuns:
  --format text|json|sarif   Formato de saída (padrão: text)
  --output arquivo           Escreve o relatório em um arquivo
  --show-secrets             Não mascara os segredos encontrados
  --no-fail                  Sempre sai com código 0
  --no-color                 Desativa cores

Códigos de saída: 0 = limpo, 1 = segredos encontrados, 2 = erro.
`

type opts struct {
	format, output        string
	show, noFail, noColor bool
	maxCommits            int
	rev                   string
	force                 bool
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return 0
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Print(usage) }
	var o opts
	fs.StringVar(&o.format, "format", "text", "")
	fs.StringVar(&o.output, "output", "", "")
	fs.BoolVar(&o.show, "show-secrets", false, "")
	fs.BoolVar(&o.noFail, "no-fail", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.IntVar(&o.maxCommits, "max-commits", 0, "")
	fs.StringVar(&o.rev, "rev", "", "")
	fs.BoolVar(&o.force, "force", false, "")
	if err := fs.Parse(reorder(args[1:])); err != nil {
		return 2
	}
	if o.noColor || o.format != "text" || o.output != "" {
		report.DisableColor()
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("leakguard", version)
		return 0
	case "rules":
		s := scanner.New(".")
		for _, r := range s.Rules {
			fmt.Printf("%-24s %-9s %s\n", r.ID, r.Severity, r.Description)
		}
		fmt.Printf("%-24s %-9s %s\n", "env-secret", "HIGH", "Valor sensível em arquivo .env")
		return 0
	case "install-hook", "uninstall-hook":
		root, err := gitscan.Root(target)
		if err != nil {
			return fail(err)
		}
		if cmd == "uninstall-hook" {
			if err := hook.Uninstall(root); err != nil {
				return fail(err)
			}
			fmt.Println("✔ Hook pre-commit do LeakGuard removido.")
			return 0
		}
		path, err := hook.Install(root, o.force)
		if err != nil {
			return fail(err)
		}
		fmt.Println("✔ Hook instalado em", path)
		fmt.Println("  A partir de agora, commits com possíveis segredos serão bloqueados.")
		return 0
	case "scan", "env":
		s := scanner.New(target)
		f, err := s.ScanPath(target)
		if err != nil {
			return fail(err)
		}
		if cmd == "env" {
			f = onlyEnv(f)
		}
		return emit(o, f, "varredura de arquivos em "+target)
	case "staged":
		root, err := gitscan.Root(target)
		if err != nil {
			return fail(err)
		}
		f, err := gitscan.ScanStaged(root, scanner.New(root))
		if err != nil {
			return fail(err)
		}
		return emit(o, f, "verificação pré-commit")
	case "history":
		root, err := gitscan.Root(target)
		if err != nil {
			return fail(err)
		}
		f, n, err := gitscan.ScanHistory(root, scanner.New(root), o.maxCommits, o.rev)
		if err != nil {
			return fail(err)
		}
		return emit(o, f, fmt.Sprintf("histórico Git (%d commits)", n))
	}
	fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n%s", cmd, usage)
	return 2
}

// reorder lets flags appear after positional args.
func reorder(a []string) []string {
	var flags, pos []string
	valued := map[string]bool{"--format": true, "-format": true, "--output": true, "-output": true, "--max-commits": true, "-max-commits": true, "--rev": true, "-rev": true}
	for i := 0; i < len(a); i++ {
		if len(a[i]) > 1 && a[i][0] == '-' {
			flags = append(flags, a[i])
			if valued[a[i]] && i+1 < len(a) {
				flags = append(flags, a[i+1])
				i++
			}
		} else {
			pos = append(pos, a[i])
		}
	}
	return append(flags, pos...)
}

func onlyEnv(f []scanner.Finding) []scanner.Finding {
	var out []scanner.Finding
	for _, x := range f {
		if scanner.IsEnvFile(x.File) {
			out = append(out, x)
		}
	}
	return out
}

func emit(o opts, f []scanner.Finding, title string) int {
	report.Sort(f)
	var w io.Writer = os.Stdout
	if o.output != "" {
		file, err := os.Create(o.output)
		if err != nil {
			return fail(err)
		}
		defer file.Close()
		w = file
	}
	var err error
	switch o.format {
	case "json":
		err = report.JSON(w, f, o.show)
	case "sarif":
		err = report.SARIF(w, f, version)
	default:
		report.Text(w, f, o.show, title)
	}
	if err != nil {
		return fail(err)
	}
	if o.output != "" {
		fmt.Fprintf(os.Stderr, "relatório salvo em %s (%d achados)\n", o.output, len(f))
	}
	if len(f) > 0 && !o.noFail {
		return 1
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "erro:", err)
	return 2
}
