// Package auth é o estágio 1 do gateway: autentica o cliente MCP e resolve a
// identidade do humano por trás do agente.
//
// DEFERIDO: não implementado no MVP-0. Será preenchido no épico E4
// (identidade/OAuth — RequireBearerToken, ClientCredentialsHandler). Até lá, a
// auditoria registra identity="anonymous". Este pacote existe para que cada
// estágio do gateway mapeie 1:1 com um pacote desde o início.
package auth
