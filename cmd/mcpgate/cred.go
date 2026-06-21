package main

// cred.go — subcomando `mcpgate cred`: enrolla e lista as credenciais do leg sul
// por (principal, upstream) no vault cifrado (E4-sul). É como o operador popula o
// vault que o gateway consulta em runtime para upstreams auth.type=per_user.
//
// O segredo NÃO é passado por flag (vazaria no histórico/argv): vem da env
// MCPGATE_CRED_VALUE ou do stdin. A chave de cifra do vault vem da env apontada
// por credentials.file.key_env na config.

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/credstore"
)

// credValueEnv é a env de onde `cred put` lê o segredo, se não vier do stdin.
const credValueEnv = "MCPGATE_CRED_VALUE" //nolint:gosec // nome de env var, não um segredo

func newCredCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cred",
		Short: "Gerencia o vault de credenciais sul por (principal, upstream) (E4-sul)",
	}
	cmd.AddCommand(newCredPutCmd(), newCredListCmd())
	return cmd
}

// openFileStore carrega a config, valida que o vault é de arquivo e o abre.
func openFileStore(configPath string) (*credstore.FileStore, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Credentials.Store != config.CredStoreFile {
		return nil, fmt.Errorf("credentials.store deve ser %q para usar `cred` (got %q)", config.CredStoreFile, cfg.Credentials.Store)
	}
	keyB64 := os.Getenv(cfg.Credentials.File.KeyEnv)
	if keyB64 == "" {
		return nil, fmt.Errorf("env %q (chave do vault) vazia", cfg.Credentials.File.KeyEnv)
	}
	key, err := credstore.DecodeKey(keyB64)
	if err != nil {
		return nil, err
	}
	return credstore.NewFileStore(cfg.Credentials.File.Path, key)
}

func newCredPutCmd() *cobra.Command {
	var configPath, upstream, principal string
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Grava a credencial sul de um (principal, upstream); segredo via env MCPGATE_CRED_VALUE ou stdin",
		RunE: func(_ *cobra.Command, _ []string) error {
			if upstream == "" || principal == "" {
				return fmt.Errorf("--upstream e --principal são obrigatórios")
			}
			secret, err := readSecret()
			if err != nil {
				return err
			}
			store, err := openFileStore(configPath)
			if err != nil {
				return err
			}
			if err := store.Put(upstream, principal, secret); err != nil {
				return err
			}
			fmt.Printf("OK: credencial gravada para principal=%q upstream=%q\n", principal, upstream)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "caminho do arquivo de configuração")
	cmd.Flags().StringVar(&upstream, "upstream", "", "nome do upstream")
	cmd.Flags().StringVar(&principal, "principal", "", "principal (humano por trás do agente)")
	return cmd
}

func newCredListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "Lista os pares (upstream, principal) no vault (sem segredos)",
		RunE: func(_ *cobra.Command, _ []string) error {
			store, err := openFileStore(configPath)
			if err != nil {
				return err
			}
			entries, err := store.List()
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("(vault vazio)")
				return nil
			}
			for _, e := range entries {
				fmt.Printf("%s\t%s\n", e.Upstream, e.Principal)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "caminho do arquivo de configuração")
	return cmd
}

// readSecret lê o segredo da env MCPGATE_CRED_VALUE ou, se vazia, da primeira
// linha do stdin. Mantém o segredo fora do argv/histórico do shell.
func readSecret() (string, error) {
	if v := os.Getenv(credValueEnv); v != "" {
		return v, nil
	}
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		s := strings.TrimRight(sc.Text(), "\r\n")
		if s != "" {
			return s, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("segredo vazio: defina %s ou passe pelo stdin", credValueEnv)
}
