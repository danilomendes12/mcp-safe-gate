// Command mcpgate é o gateway de governança para MCP.
//
// No MVP-0 expõe dois subcomandos: `serve` (sobe o proxy em stdio) e
// `validate-config` (valida o arquivo estaticamente, sem rede).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/proxy"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mcpgate",
		Short:         "Gateway de governança open source para MCP",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServeCmd(), newValidateConfigCmd())
	return root
}

// defaultConfigPath resolve o default da flag --config. Permite apontar o
// arquivo via env MCPGATE_CONFIG, útil quando um wrapper (ex.: o MCP Inspector)
// reserva a flag --config para si e não a repassa ao processo do gateway.
func defaultConfigPath() string {
	if p := os.Getenv("MCPGATE_CONFIG"); p != "" {
		return p
	}
	return "configs/mcpgate.example.yaml"
}

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Sobe o gateway (transporte stdio) e fronteia os upstreams configurados",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "caminho do arquivo de configuração (ou via env MCPGATE_CONFIG)")
	return cmd
}

func newValidateConfigCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "validate-config",
		Short: "Valida o arquivo de configuração estaticamente (sem rede)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := config.Load(configPath); err != nil {
				return err
			}
			fmt.Println("OK")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "caminho do arquivo de configuração (ou via env MCPGATE_CONFIG)")
	return cmd
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	auditLog, err := audit.New(cfg.Audit)
	if err != nil {
		return err
	}
	defer func() { _ = auditLog.Close() }()

	// Encerramento gracioso em SIGINT/SIGTERM: cancela o ctx, o que faz o
	// server.Run retornar e dispara o fechamento das sessões dos upstreams.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	p, err := proxy.New(ctx, cfg, auditLog)
	if err != nil {
		return err
	}
	defer func() { _ = p.Close() }()

	if err := p.Run(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("servidor: %w", err)
	}
	return nil
}
