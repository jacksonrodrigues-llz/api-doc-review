# Vulnerabilidade de Controle de Acesso

## 🎯 Vulnerabilidade Identificada

**Endpoint Afetado**: `https://api.hml.llzgarantidora.com/api/funcionarios?size=1000`

**Problema**: 
- Acesso não autorizado a rotas administrativas
- Usuários operadores acessando funcionalidades além de suas permissões
- Possibilidade de acessar URLs internas sem autenticação

**Impacto**: Crítico - Acesso não autorizado a rotas não permitidas

## 🛡️ Soluções Implementadas

### Rota Principal Protegida

**Rota:** `/api/funcionarios` (GET com filtros)

**Proteção aplicada:** `@PreAuthorize("@authz.podeAcessarComEmail()")`

Esta anotação garante que apenas usuários do departamento TECNOLOGIA possam acessar a listagem de funcionários.

## Abordagem de Segurança Implementada

### 1. Autenticação JWT

- Tokens validados contra o AWS Cognito
- Verificação de assinatura e expiração automática
- Extração segura de claims do token

### 2. Autorização Baseada em Roles

- Roles geradas dinamicamente: `ROLE_DEPARTAMENTO`
- Exemplo: `ROLE_TECNOLOGIA`
- Controle granular por departamento e função

### 3. Validação de Contexto

- Verificação de correspondência entre email do token e funcionário
- Validação de departamento específico para acesso
- Logs detalhados para auditoria

## Fluxo de Segurança

1. **Requisição recebida** → Interceptor registra a requisição
2. **Token JWT validado** → Spring Security valida assinatura e expiração
3. **Claims extraídos** → CognitoAutorizacoesService processa o token
4. **Funcionário localizado** → Busca por email no banco de dados
5. **Role gerada** → Formato ROLE_DEPARTAMENTO
6. **Autorização verificada** → @PreAuthorize valida permissões
7. **Acesso concedido/negado** → Baseado nas validações


## Resultado da Implementação

A implementação resolve completamente o problema identificado no pentest:

- **Controle de acesso implementado**: Todas as rotas administrativas protegidas
- **Validação de permissões**: Sistema hierárquico baseado em departamento
- **Autenticação obrigatória**: JWT tokens validados em todas as rotas protegidas

O usuário operador agora só consegue acessar funcionalidades do seu departamento específico, eliminando a vulnerabilidade de acesso não autorizado a rotas administrativas.
