// Package policy são os estágios 2 e 3 do gateway: RBAC por ferramenta
// (default deny) e descoberta filtrada de tools/list.
//
// DEFERIDO: não implementado no MVP-0. Será preenchido nos épicos E2 (motor de
// política / rejeição de tools/call) e E3 (descoberta filtrada). No MVP, o
// campo `policies` da config é parseado mas ignorado (apenas um aviso é logado).
// Este pacote existe para que cada estágio mapeie 1:1 com um pacote desde já.
package policy
