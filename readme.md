# Laboratório de Engenharia de Deteção de Brute Force SSH com Splunk

## Visão Geral

Este projeto demonstra um fluxo completo de deteção em ambiente SOC para atividade de brute force SSH utilizando Splunk.

O laboratório inclui descoberta de serviço com Nmap, simulação controlada de brute force SSH com Metasploit, ingestão de logs no Splunk, criação de lógica de deteção com SPL, configuração de alerta e recolha de evidências.

## Objetivo

O objetivo deste laboratório foi detetar tentativas repetidas de login SSH falhado e gerar um alerta quando fosse observado comportamento compatível com brute force.

## Ambiente de Laboratório

- Kali Linux
- Splunk Enterprise 9.3.1
- OpenSSH Server
- Nmap
- Metasploit Framework
- SPL
- Host Windows utilizado para teste externo de SSH

## Âmbito do Laboratório

Este laboratório foi realizado num ambiente local e controlado.

O alvo utilizado foi a minha própria máquina Kali Linux, com OpenSSH e Splunk em execução. O Nmap e o Metasploit foram utilizados apenas contra a minha própria máquina de laboratório, com finalidade educativa e de engenharia de deteção.

## Metodologia

1. Utilização do Nmap para confirmar que o serviço SSH estava exposto na porta 22.
2. Utilização do Metasploit para gerar tentativas controladas de login SSH falhado.
3. Ingestão dos logs de autenticação SSH no Splunk.
4. Extração dos campos de IP de origem e utilizador através de SPL.
5. Criação de uma query de deteção para tentativas repetidas de login SSH falhado.
6. Configuração de um alerta agendado com severidade alta.
7. Validação do alerta na secção Triggered Alerts do Splunk.
8. Exportação de evidências e screenshots para documentação.

## Descoberta de Serviço

O Nmap foi utilizado para validar que o host alvo tinha o serviço SSH exposto na porta 22.

```bash
nmap -sV -p 22 192.168.1.4 -oN evidence/nmap_ssh_service_scan.txt
```

### Resultado

```text
22/tcp open  ssh  OpenSSH 10.2p1 Debian 6
```

## Simulação do Brute Force

O Metasploit foi utilizado num laboratório local controlado para gerar tentativas falhadas de login SSH contra o meu próprio serviço SSH.

### Módulo utilizado

```text
auxiliary/scanner/ssh/ssh_login
```

O objetivo desta etapa não foi exploração. A finalidade foi gerar logs de falha de autenticação que pudessem ser ingeridos e detetados pelo Splunk.

## Fonte de Dados

O Splunk monitorizou o seguinte ficheiro de log SSH:

```text
/var/log/ssh_bruteforce.log
```

### Sourcetype personalizado

```text
ssh_Bruteforce
```

## Query de Deteção

```spl
index=main sourcetype=ssh_Bruteforce "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts earliest(_time) as first_attempt latest(_time) as last_attempt by src_ip, user
| where failed_attempts >= 5
| convert ctime(first_attempt) ctime(last_attempt)
| sort -failed_attempts
```

## Lógica de Deteção

A deteção identifica possível atividade de brute force SSH através dos seguintes passos:

- Pesquisa por tentativas falhadas de login SSH.
- Extração do endereço IP de origem.
- Extração do nome de utilizador alvo.
- Contagem de tentativas falhadas por IP de origem e utilizador.
- Geração de deteção quando o número de tentativas falhadas é maior ou igual a 5.

## Configuração do Alerta

| Campo | Valor |
|---|---|
| Nome do alerta | SSH BRUTE FORCE DETECTION |
| Tipo de alerta | Scheduled |
| Agendamento | A cada 5 minutos |
| Condição de disparo | Número de resultados maior que 0 |
| Severidade | High |
| Ação | Add to Triggered Alerts |
| Throttling | Ativado para reduzir alertas repetidos |

## Resultados

A deteção identificou com sucesso múltiplas tentativas falhadas de login SSH.

### Exemplo de resultados

| IP de Origem | Utilizador | Tentativas Falhadas |
|---|---|---|
| 127.0.0.1 | admin | 12 |
| 192.168.1.2 | teste | 6 |
| 192.168.1.4 | admin | 7 |

## Mapeamento MITRE ATT&CK

| Técnica | Descrição |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |

## Evidências

### Screenshots

```text
01_nmap_ssh_service_scan.png
02_raw_ssh_logs_ingested.png
03_bruteforce_detection_result.png
04_alert_configuration.png
05_triggered_alerts.png
06_metasploit_detection_result.png
```

### Evidências Exportadas

```text
nmap_ssh_service_scan.txt
bruteforce_detection_results.csv
metasploit_bruteforce_detection_results.csv
raw_ssh_failed_login_events_1.txt
raw_ssh_failed_login_events_2.txt
```

## Competências Demonstradas

- Descoberta de serviço com Nmap.
- Simulação controlada com Metasploit.
- Ingestão de logs no Splunk.
- Criação de queries SPL.
- Extração de campos com `rex`.
- Lógica de deteção de brute force SSH.
- Criação e validação de alertas.
- Configuração de severidade de alerta.
- Fluxo básico de trabalho em ambiente SOC.
- Mapeamento com MITRE ATT&CK.

## Estrutura do Projeto

```text
.
├── evidence
│   ├── bruteforce_detection_results.csv
│   ├── metasploit_bruteforce_detection_results.csv
│   ├── nmap_ssh_service_scan.txt
│   ├── raw_ssh_failed_login_events_1.txt
│   └── raw_ssh_failed_login_events_2.txt
├── screenshots
│   ├── 01_nmap_ssh_service_scan.png
│   ├── 02_raw_ssh_logs_ingested.png
│   ├── 03_bruteforce_detection_result.png
│   ├── 04_alert_configuration.png
│   ├── 05_triggered_alerts.png
│   └── 06_metasploit_detection_result.png
├── spl
│   └── ssh_bruteforce_detection.spl
└── wordlists
    ├── passwords.txt
    └── users.txt
```

## Conclusão

Este laboratório demonstra um fluxo prático de engenharia de deteção para atividade de brute force SSH.

O projeto cobre descoberta de serviço, simulação controlada, ingestão de logs, criação de lógica de deteção com SPL, configuração de alerta e validação através dos alertas disparados no Splunk.

## Aviso Legal

Este projeto foi realizado exclusivamente em ambiente laboratorial, local e controlado, para fins educativos e defensivos. Nenhum sistema real, rede pública ou ambiente de produção foi afetado.
