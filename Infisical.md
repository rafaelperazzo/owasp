# Uso básico do Infisical

## Criar sua conta

- [INFISICAL](https://app.infisical.com/signup)

## Criar o(s) segredo(s) dentro do projeto

- Menu Secrets
- Add Secret

## Criar um service token para o projeto

- Menu Secrets - Access Control - Service Tokens
- Guarde o token de forma segura

## Logar no client infisical

```console
export INFISICAL_TOKEN=TOKEN_GERADO_NO_PASSO_ANTERIOR
```

## Baixar o cliente infisical

- (https://infisical.com/docs/cli/overview)[https://infisical.com/docs/cli/overview]


## Iniciar o infisical no seu projeto de app

```console
cd pastaDoSeuApp
infisical init
```

## Baixar os segredos necessários para seu projeto

```console
infisical secrets get NOME_DO_SEGREDO --plain
```

## Exportar para um arquivo .env

```console
infisical export > .env
```

## Referência da documentação

- (https://infisical.com/docs/documentation/getting-started/introduction)[https://infisical.com/docs/documentation/getting-started/introduction]