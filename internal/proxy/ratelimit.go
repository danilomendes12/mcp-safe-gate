package proxy

import (
	"sync"

	"golang.org/x/time/rate"

	"github.com/danilomendes/mcpgate/internal/config"
)

// perAgentLimiter é um token bucket por principal, in-process e puro-Go.
// Mapeia a defesa contra DoS por exaustão de recursos (SAFE-MCP / Impact,
// ATK-TA0040): um agente abusivo não derruba o gateway nem afoga os demais.
//
// Sem store externo (Tier 0): o estado vive no processo. Cada principal ganha
// seu próprio rate.Limiter sob demanda, protegido por um mutex.
type perAgentLimiter struct {
	rps   rate.Limit
	burst int

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// newPerAgentLimiter constrói o limiter a partir da config. RPS<=0 => desligado.
func newPerAgentLimiter(cfg config.RateLimit) *perAgentLimiter {
	return &perAgentLimiter{
		rps:      rate.Limit(cfg.RPS),
		burst:    cfg.Burst,
		limiters: make(map[string]*rate.Limiter),
	}
}

// enabled informa se o rate limiting está ativo.
func (l *perAgentLimiter) enabled() bool { return l.rps > 0 }

// allow consome um token do bucket do principal. Devolve true se havia token
// (admissão liberada) ou se o limiting está desligado.
func (l *perAgentLimiter) allow(principal string) bool {
	if !l.enabled() {
		return true
	}
	l.mu.Lock()
	lim, ok := l.limiters[principal]
	if !ok {
		lim = rate.NewLimiter(l.rps, l.burst)
		l.limiters[principal] = lim
	}
	l.mu.Unlock()
	return lim.Allow()
}
