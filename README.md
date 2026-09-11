# 🛡️ Laboratório de Hardening de Servidor Linux

> Laboratório prático de **avaliação, correção, validação e documentação de segurança em servidor Linux**.

**Tecnologias:** Ubuntu Server 24.04 LTS · SSH · UFW · Fail2ban · Auditd · Sysctl · Nmap

**Metodologia:**

```text
Baseline → Hardening → Validação → Evidências → Relatório
```

---

## 📌 1. Objetivo

Este laboratório tem como objetivo implementar práticas de **hardening em um servidor Linux**, reduzindo sua superfície de ataque e melhorando os controles de segurança.

Durante o laboratório serão praticados:

* Atualização e gerenciamento de pacotes;
* Gestão de usuários e privilégios;
* Princípio do menor privilégio;
* Hardening do SSH;
* Autenticação por chave pública;
* Configuração de firewall;
* Remoção de serviços desnecessários;
* Proteção contra brute force;
* Auditoria de eventos;
* Hardening básico do kernel;
* Identificação de portas abertas;
* Validação das configurações;
* Coleta de evidências;
* Documentação técnica.

---

# 🏗️ 2. Arquitetura do Laboratório

```text
                         INTERNET
                             │
                             ▼
                    ┌────────────────┐
                    │    FIREWALL    │
                    │ UFW / Firewall │
                    └───────┬────────┘
                            │
             ┌──────────────┴──────────────┐
             │                             │
             ▼                             ▼
      VLAN ADMIN                     VLAN SERVERS
   192.168.10.0/24                  192.168.20.0/24
             │                             │
             │ SSH                         │
             ▼                             ▼
    ┌────────────────┐             ┌─────────────────┐
    │ Administrador  │────────────▶│  srv-linux01    │
    │   Linux Mint   │    SSH      │ Ubuntu 24.04 LTS│
    │ 192.168.10.10  │             │ 192.168.20.10   │
    └────────────────┘             └────────┬────────┘
                                            │
                           ┌────────────────┼────────────────┐
                           │                │                │
                           ▼                ▼                ▼
                         UFW             Fail2ban          Auditd
                       Firewall          Anti-Brute        Auditoria
                           │
                           ▼
                        Sysctl
                     Kernel Hardening
```

> A segmentação por VLAN é opcional neste laboratório. Em uma VM simples, o servidor pode permanecer em uma única rede isolada.

---

# 💻 3. Requisitos

## Servidor

| Recurso    | Configuração            |
| ---------- | ----------------------- |
| Sistema    | Ubuntu Server 24.04 LTS |
| CPU        | 2 vCPU                  |
| RAM        | 2 GB                    |
| Disco      | 20 GB                   |
| Hostname   | `srv-linux01`           |
| IP exemplo | `192.168.20.10`         |

## Máquina administrativa

Linux Mint, Ubuntu ou outra distribuição Linux com:

```bash
ssh
nmap
```

---

# ⚠️ 4. Preparação

Antes de iniciar:

1. Instale o Ubuntu Server.
2. Configure a rede.
3. Defina o hostname.
4. Configure o acesso SSH.
5. Garanta acesso administrativo à VM.
6. Crie um **snapshot da VM**.

Nome sugerido:

```text
00-before-hardening
```

O snapshot permite restaurar o ambiente caso alguma alteração impeça o acesso ao servidor.

---

# 🔎 5. FASE 1 — BASELINE

> **Não faça hardening antes de terminar esta etapa.**

O objetivo do baseline é registrar o estado original do servidor.

---

## 5.1 Identificar o sistema

```bash
hostnamectl
```

```bash
uname -a
```

```bash
cat /etc/os-release
```

Registrar:

* Hostname;
* Sistema operacional;
* Versão;
* Kernel;
* Arquitetura.

---

## 5.2 Identificar interfaces de rede

```bash
ip addr
```

```bash
ip route
```

Registrar:

```text
IP:
Gateway:
Interface:
Rede:
```

---

## 5.3 Identificar portas abertas

```bash
ss -tulpn
```

Também pode ser utilizado:

```bash
sudo ss -tulpn
```

Registrar todas as portas TCP/UDP encontradas.

Exemplo:

```text
22/tcp
80/tcp
443/tcp
```

---

## 5.4 Identificar serviços ativos

```bash
systemctl --type=service --state=running
```

Para verificar serviços habilitados:

```bash
systemctl list-unit-files --type=service --state=enabled
```

Perguntas:

* Quais serviços estão ativos?
* Eles são necessários?
* Existe algum serviço expondo uma porta desnecessariamente?
* Existe algum serviço que deveria estar desativado?

---

## 5.5 Identificar usuários

```bash
cat /etc/passwd
```

Usuários com shell:

```bash
grep -E '/bin/bash|/bin/sh' /etc/passwd
```

Verificar grupo administrativo:

```bash
getent group sudo
```

Identificar usuários com UID 0:

```bash
awk -F: '$3 == 0 {print $1}' /etc/passwd
```

O resultado esperado deve conter apenas:

```text
root
```

---

## 5.6 Verificar SSH

```bash
sudo systemctl status ssh
```

Verificar configuração efetiva:

```bash
sudo sshd -T
```

Filtrar parâmetros importantes:

```bash
sudo sshd -T | grep -E \
'permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication|x11forwarding'
```

---

## 5.7 Verificar firewall

```bash
sudo ufw status verbose
```

Caso ainda não esteja instalado:

```bash
which ufw
```

---

## 5.8 Verificar atualizações

```bash
sudo apt update
```

Depois:

```bash
apt list --upgradable
```

Registrar a quantidade de pacotes pendentes.

---

## 5.9 Criar evidência do baseline

Criar:

```text
01-baseline/
└── baseline.txt
```

Uma maneira simples de gerar informações:

```bash
{
    echo "===== HOSTNAME ====="
    hostnamectl

    echo "===== KERNEL ====="
    uname -a

    echo "===== NETWORK ====="
    ip addr

    echo "===== ROUTES ====="
    ip route

    echo "===== PORTS ====="
    sudo ss -tulpn

    echo "===== SERVICES ====="
    systemctl --type=service --state=running

    echo "===== USERS ====="
    cat /etc/passwd

    echo "===== SUDO ====="
    getent group sudo

    echo "===== FIREWALL ====="
    sudo ufw status verbose

    echo "===== UPDATES ====="
    apt list --upgradable
} | tee 01-baseline/baseline.txt
```

---

# 🔐 6. FASE 2 — ATUALIZAÇÃO DO SISTEMA

Atualizar os repositórios:

```bash
sudo apt update
```

Atualizar pacotes:

```bash
sudo apt full-upgrade -y
```

Remover pacotes desnecessários:

```bash
sudo apt autoremove -y
```

Limpar cache:

```bash
sudo apt autoclean
```

Verificar novamente:

```bash
apt list --upgradable
```

---

# 🔄 7. Atualizações Automáticas

Instalar:

```bash
sudo apt install unattended-upgrades apt-listchanges -y
```

Habilitar:

```bash
sudo dpkg-reconfigure unattended-upgrades
```

Verificar:

```bash
systemctl status unattended-upgrades
```

---

# 👤 8. FASE 3 — USUÁRIO ADMINISTRATIVO

Criar usuário:

```bash
sudo adduser adminlab
```

Adicionar ao grupo sudo:

```bash
sudo usermod -aG sudo adminlab
```

Verificar:

```bash
id adminlab
```

Testar:

```bash
su - adminlab
```

Executar:

```bash
sudo whoami
```

Resultado esperado:

```text
root
```

O administrador continua realizando login como:

```text
adminlab
```

e utiliza `sudo` somente quando necessário.

---

# 🔑 9. FASE 4 — AUTENTICAÇÃO SSH POR CHAVE

## 9.1 Criar chave na máquina administrativa

Na máquina Linux Mint:

```bash
ssh-keygen -t ed25519
```

Aceite o caminho padrão ou escolha um caminho específico.

Recomenda-se utilizar uma passphrase.

---

## 9.2 Copiar chave para o servidor

```bash
ssh-copy-id adminlab@192.168.20.10
```

Teste:

```bash
ssh adminlab@192.168.20.10
```

Confirme que a autenticação funciona **antes de desabilitar senha**.

---

# 🔒 10. FASE 5 — HARDENING DO SSH

Criar backup:

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

Editar:

```bash
sudo nano /etc/ssh/sshd_config
```

Configurações sugeridas:

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowUsers adminlab
```

---

## 10.1 Validar configuração

Antes de reiniciar:

```bash
sudo sshd -t
```

Se não houver saída, a sintaxe está válida.

---

## 10.2 Reiniciar SSH

```bash
sudo systemctl restart ssh
```

Verificar:

```bash
sudo systemctl status ssh
```

---

## 10.3 Validar configuração efetiva

```bash
sudo sshd -T | grep -E \
'permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication|x11forwarding'
```

Resultado esperado:

```text
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
maxauthtries 3
x11forwarding no
```

---

# 🧱 11. FASE 6 — FIREWALL UFW

Instalar:

```bash
sudo apt install ufw -y
```

Definir política padrão:

```bash
sudo ufw default deny incoming
```

```bash
sudo ufw default allow outgoing
```

Permitir SSH:

```bash
sudo ufw allow 22/tcp
```

Ativar:

```bash
sudo ufw enable
```

Verificar:

```bash
sudo ufw status verbose
```

---

## 11.1 Restringir SSH à rede administrativa

Depois de confirmar que o firewall funciona:

```bash
sudo ufw delete allow 22/tcp
```

Permitir somente a rede administrativa:

```bash
sudo ufw allow from 192.168.10.0/24 to any port 22 proto tcp
```

Verificar:

```bash
sudo ufw status numbered
```

---

# 🧹 12. FASE 7 — SERVIÇOS DESNECESSÁRIOS

Listar serviços:

```bash
systemctl --type=service --state=running
```

Identificar portas:

```bash
sudo ss -tulpn
```

Para um serviço que foi analisado e considerado desnecessário:

```bash
sudo systemctl disable --now NOME_DO_SERVICO
```

Exemplo:

```bash
sudo systemctl disable --now cups
```

Verificar:

```bash
systemctl status cups
```

> **Importante:** não desabilite serviços sem entender sua finalidade. O objetivo do hardening é reduzir a superfície de ataque sem comprometer a disponibilidade.

---

# 🛡️ 13. FASE 8 — FAIL2BAN

Instalar:

```bash
sudo apt install fail2ban -y
```

Habilitar:

```bash
sudo systemctl enable --now fail2ban
```

Verificar:

```bash
sudo systemctl status fail2ban
```

Ver jails:

```bash
sudo fail2ban-client status
```

Verificar SSH:

```bash
sudo fail2ban-client status sshd
```

O objetivo é detectar e bloquear comportamentos associados a tentativas repetidas de autenticação.

---

# 📋 14. FASE 9 — AUDITORIA COM AUDITD

Instalar:

```bash
sudo apt install auditd audispd-plugins -y
```

Habilitar:

```bash
sudo systemctl enable --now auditd
```

Verificar:

```bash
sudo systemctl status auditd
```

Ver estado:

```bash
sudo auditctl -s
```

Pesquisar eventos de login:

```bash
sudo ausearch -m USER_LOGIN
```

Pesquisar eventos relacionados a autenticação:

```bash
sudo ausearch -m USER_AUTH
```

Visualizar regras:

```bash
sudo auditctl -l
```

---

# ⚙️ 15. FASE 10 — HARDENING DO KERNEL

Criar arquivo:

```bash
sudo nano /etc/sysctl.d/99-hardening.conf
```

Adicionar:

```text
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1

kernel.randomize_va_space = 2
```

Aplicar:

```bash
sudo sysctl --system
```

---

## 15.1 Validar

```bash
sysctl net.ipv4.conf.all.accept_redirects
```

```bash
sysctl net.ipv4.conf.all.send_redirects
```

```bash
sysctl net.ipv4.conf.all.accept_source_route
```

```bash
sysctl kernel.randomize_va_space
```

Os parâmetros deverão apresentar os valores configurados.

---

# 🔍 16. FASE 11 — VALIDAÇÃO PÓS-HARDENING

Agora repetir o baseline.

---

## 16.1 Portas

```bash
sudo ss -tulpn
```

Comparar com:

```text
01-baseline/baseline.txt
```

Objetivo:

```text
Reduzir portas expostas sem necessidade.
```

---

## 16.2 Serviços

```bash
systemctl --type=service --state=running
```

Comparar antes/depois.

---

## 16.3 Firewall

```bash
sudo ufw status verbose
```

Esperado:

```text
Status: active
```

---

## 16.4 SSH

```bash
sudo sshd -T | grep -E \
'permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication|x11forwarding'
```

Esperado:

```text
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
maxauthtries 3
x11forwarding no
```

---

## 16.5 Fail2ban

```bash
sudo fail2ban-client status
```

Depois:

```bash
sudo fail2ban-client status sshd
```

---

## 16.6 Auditd

```bash
sudo auditctl -s
```

```bash
sudo auditctl -l
```

---

## 16.7 Kernel

```bash
sysctl net.ipv4.conf.all.accept_redirects
```

```bash
sysctl net.ipv4.conf.all.send_redirects
```

```bash
sysctl kernel.randomize_va_space
```

---

# 🌐 17. FASE 12 — TESTE COM NMAP

Na máquina administrativa:

```bash
nmap -sV 192.168.20.10
```

Para uma análise mais completa:

```bash
sudo nmap -sS -sV -O 192.168.20.10
```

Registrar o resultado:

```text
03-validation/nmap-after.txt
```

Exemplo:

```bash
nmap -sV 192.168.20.10 | tee 03-validation/nmap-after.txt
```

Compare com o resultado obtido antes do hardening.

---

# 📊 18. Comparação Antes × Depois

Criar uma tabela no relatório:

| Controle              | Antes      | Depois             | Resultado |
| --------------------- | ---------- | ------------------ | --------- |
| Root via SSH          | Permitido  | Bloqueado          | ✅         |
| Senha SSH             | Permitida  | Desabilitada       | ✅         |
| Chave SSH             | Opcional   | Obrigatória        | ✅         |
| Firewall              | Inativo    | Ativo              | ✅         |
| Portas desnecessárias | Existentes | Removidas          | ✅         |
| Fail2ban              | Ausente    | Ativo              | ✅         |
| Auditd                | Ausente    | Ativo              | ✅         |
| Sysctl                | Padrão     | Hardening aplicado | ✅         |
| Atualizações          | Pendentes  | Atualizado         | ✅         |

---

# 📁 19. Coleta de Evidências

Criar:

```text
03-validation/
```

Estrutura:

```text
03-validation/
├── ports-after.txt
├── services-after.txt
├── ssh-after.txt
├── firewall-after.txt
├── fail2ban-after.txt
├── audit-after.txt
├── sysctl-after.txt
└── nmap-after.txt
```

Exemplo:

```bash
sudo ss -tulpn > 03-validation/ports-after.txt
```

```bash
systemctl --type=service --state=running \
> 03-validation/services-after.txt
```

```bash
sudo ufw status verbose \
> 03-validation/firewall-after.txt
```

```bash
sudo fail2ban-client status \
> 03-validation/fail2ban-after.txt
```

```bash
sudo auditctl -s \
> 03-validation/audit-after.txt
```

```bash
sysctl -a 2>/dev/null | grep -E \
'accept_redirects|send_redirects|accept_source_route|rp_filter|randomize_va_space' \
> 03-validation/sysctl-after.txt
```

---

# 📝 20. Relatório Técnico

Criar:

```text
04-report/hardening-report.md
```

O relatório deverá conter:

```text
1. Objetivo
2. Escopo
3. Arquitetura
4. Características do servidor
5. Baseline
6. Achados
7. Avaliação de risco
8. Medidas de hardening
9. Evidências
10. Testes realizados
11. Comparação antes/depois
12. Riscos residuais
13. Recomendações
14. Conclusão
```

---

# ⚠️ 21. Riscos e Cuidados

Antes de alterações críticas:

```text
Criar snapshot.
```

Antes de alterar SSH:

```text
Manter uma sessão SSH administrativa aberta.
```

Antes de ativar firewall:

```text
Garantir que a porta SSH esteja liberada.
```

Antes de desabilitar serviços:

```text
Verificar dependências.
```

Nunca executar alterações de segurança em ambiente produtivo sem:

* Autorização;
* Planejamento;
* Backup;
* Janela de manutenção;
* Plano de rollback.

---


## ⚠️ Aviso

Este laboratório deve ser executado exclusivamente em ambiente próprio, controlado e autorizado.

Não aplique as configurações diretamente em servidores de produção sem avaliação de impacto, backup, janela de manutenção e plano de rollback.

---

**Linux · Cybersecurity · Infrastructure · Hardening · Security Assessment**
