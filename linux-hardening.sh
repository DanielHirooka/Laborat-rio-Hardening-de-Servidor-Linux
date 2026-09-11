#!/usr/bin/env bash
#
# linux-hardening.sh
# Laboratório de Hardening de Servidor Linux - Ubuntu Server 24.04 LTS
#
# Fluxo:
#   Baseline -> Updates -> Admin User -> SSH -> UFW -> Services
#   -> Fail2ban -> Auditd -> Sysctl -> Validation -> Evidence
#
# Uso:
#   sudo bash linux-hardening.sh
#
# Variáveis opcionais:
#   ADMIN_USER=adminlab
#   SSH_PORT=22
#   SSH_ALLOWED_FROM=192.168.10.0/24
#   DISABLE_SSH_PASSWORD=true
#   INSTALL_UNATTENDED_UPGRADES=true
#
# ATENÇÃO:
#   Teste primeiro em VM/snapshot. Se SSH_ALLOWED_FROM ou a autenticação
#   estiverem incorretos, você pode perder o acesso remoto.
#

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.0"
LAB_ROOT="${LAB_ROOT:-/opt/linux-hardening-lab}"
BASELINE_DIR="${LAB_ROOT}/01-baseline"
HARDENING_DIR="${LAB_ROOT}/02-hardening"
VALIDATION_DIR="${LAB_ROOT}/03-validation"
REPORT_DIR="${LAB_ROOT}/04-report"
LOG_FILE="${LAB_ROOT}/hardening-execution.log"

ADMIN_USER="${ADMIN_USER:-adminlab}"
SSH_PORT="${SSH_PORT:-22}"
DISABLE_SSH_PASSWORD="${DISABLE_SSH_PASSWORD:-true}"
INSTALL_UNATTENDED_UPGRADES="${INSTALL_UNATTENDED_UPGRADES:-true}"

# Se executado via SSH, usa o IP do cliente atual como padrão.
CURRENT_SSH_CLIENT_IP=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    CURRENT_SSH_CLIENT_IP="$(awk '{print $1}' <<< "$SSH_CONNECTION")"
fi

if [[ -n "$CURRENT_SSH_CLIENT_IP" ]]; then
    DEFAULT_SSH_ALLOWED_FROM="${CURRENT_SSH_CLIENT_IP}/32"
else
    DEFAULT_SSH_ALLOWED_FROM=""
fi

SSH_ALLOWED_FROM="${SSH_ALLOWED_FROM:-$DEFAULT_SSH_ALLOWED_FROM}"

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    echo "[$(timestamp)] $*" | tee -a "$LOG_FILE"
}

die() {
    log "ERRO: $*"
    exit 1
}

trap 'die "Falha na linha $LINENO. Verifique ${LOG_FILE}."' ERR

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Execute como root: sudo bash $0"
}

check_os() {
    [[ -f /etc/os-release ]] || die "Não foi possível identificar o sistema operacional."
    # shellcheck disable=SC1091
    source /etc/os-release

    if [[ "${ID:-}" != "ubuntu" ]]; then
        die "Este script foi desenvolvido para Ubuntu Server. Detectado: ${ID:-desconhecido}"
    fi

    log "Sistema detectado: ${PRETTY_NAME:-Ubuntu}"
}

confirm_start() {
    echo
    echo "=============================================================="
    echo " Linux Server Hardening - laboratório"
    echo " Versão: ${SCRIPT_VERSION}"
    echo "=============================================================="
    echo
    echo "Este script irá:"
    echo "  - coletar baseline"
    echo "  - atualizar pacotes"
    echo "  - criar/ajustar usuário administrativo"
    echo "  - configurar SSH"
    echo "  - habilitar UFW"
    echo "  - instalar/configurar Fail2ban"
    echo "  - instalar/configurar Auditd"
    echo "  - aplicar Sysctl"
    echo "  - coletar evidências pós-hardening"
    echo
    echo "RECOMENDAÇÃO: crie um snapshot da VM antes de continuar."
    echo

    read -r -p "Digite HARDEN para continuar: " answer
    [[ "$answer" == "HARDEN" ]] || die "Execução cancelada pelo usuário."

    if [[ -z "$SSH_ALLOWED_FROM" ]]; then
        echo
        echo "Não foi possível determinar automaticamente a origem permitida para SSH."
        read -r -p "Informe a rede/IP permitido para SSH (ex.: 192.168.10.0/24): " SSH_ALLOWED_FROM
        [[ -n "$SSH_ALLOWED_FROM" ]] || die "SSH_ALLOWED_FROM não pode ficar vazio."
    fi

    echo
    echo "SSH será permitido pelo UFW somente de: ${SSH_ALLOWED_FROM}"
    echo "Usuário administrativo: ${ADMIN_USER}"
    echo "Porta SSH: ${SSH_PORT}"
    echo

    if [[ "$DISABLE_SSH_PASSWORD" == "true" ]]; then
        echo "A autenticação SSH por senha será DESABILITADA."
        echo "Certifique-se de que a chave pública do usuário ${ADMIN_USER} já funciona."
        read -r -p "Confirma essa alteração? [s/N]: " ssh_confirm
        [[ "$ssh_confirm" =~ ^[sS]$ ]] || {
            log "Autenticação por senha não será desabilitada."
            DISABLE_SSH_PASSWORD="false"
        }
    fi
}

prepare_dirs() {
    mkdir -p "$BASELINE_DIR" "$HARDENING_DIR" "$VALIDATION_DIR" "$REPORT_DIR"
    touch "$LOG_FILE"
    chmod 700 "$LAB_ROOT"
    log "Diretórios de evidências preparados em ${LAB_ROOT}"
}

snapshot_warning() {
    cat > "${LAB_ROOT}/SNAPSHOT-RECOMMENDATION.txt" <<EOF
Laboratório de Linux Hardening
Data: $(timestamp)

Antes de alterações críticas, recomenda-se criar um snapshot da VM.

Em caso de perda de acesso SSH ou configuração incorreta:
1. Acesse o console da VM/hypervisor.
2. Corrija a configuração.
3. Ou restaure o snapshot anterior.

SSH permitido pelo UFW:
${SSH_ALLOWED_FROM}
EOF
}

run_baseline() {
    log "Coletando baseline..."

    {
        echo "===== BASELINE - $(timestamp) ====="
        echo
        echo "===== HOSTNAMECTL ====="
        hostnamectl || true
        echo
        echo "===== OS-RELEASE ====="
        cat /etc/os-release
        echo
        echo "===== KERNEL ====="
        uname -a
        echo
        echo "===== NETWORK ====="
        ip addr
        echo
        echo "===== ROUTES ====="
        ip route
        echo
        echo "===== PORTS ====="
        ss -tulpn
        echo
        echo "===== RUNNING SERVICES ====="
        systemctl --type=service --state=running
        echo
        echo "===== ENABLED SERVICES ====="
        systemctl list-unit-files --type=service --state=enabled
        echo
        echo "===== USERS ====="
        cat /etc/passwd
        echo
        echo "===== SUDO GROUP ====="
        getent group sudo || true
        echo
        echo "===== UID 0 ====="
        awk -F: '$3 == 0 {print $1}' /etc/passwd
        echo
        echo "===== SSH STATUS ====="
        systemctl status ssh --no-pager || true
        echo
        echo "===== SSH EFFECTIVE CONFIG ====="
        sshd -T 2>/dev/null || true
        echo
        echo "===== FIREWALL ====="
        ufw status verbose 2>&1 || true
        echo
        echo "===== UPGRADABLE PACKAGES ====="
        apt list --upgradable 2>/dev/null || true
    } > "${BASELINE_DIR}/baseline.txt"

    # Scan local, se nmap estiver disponível.
    if command -v nmap >/dev/null 2>&1; then
        nmap -sV 127.0.0.1 > "${BASELINE_DIR}/nmap-local.txt" 2>&1 || true
    fi

    log "Baseline salvo em ${BASELINE_DIR}/baseline.txt"
}

update_system() {
    log "Atualizando sistema..."
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get full-upgrade -y
    apt-get autoremove -y
    apt-get autoclean

    if [[ "$INSTALL_UNATTENDED_UPGRADES" == "true" ]]; then
        apt-get install -y unattended-upgrades apt-listchanges
        dpkg-reconfigure -f noninteractive unattended-upgrades || true
    fi

    log "Atualização concluída."
}

create_admin_user() {
    log "Configurando usuário administrativo: ${ADMIN_USER}"

    if ! id "$ADMIN_USER" >/dev/null 2>&1; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
        log "Usuário ${ADMIN_USER} criado."
    else
        log "Usuário ${ADMIN_USER} já existe."
    fi

    usermod -aG sudo "$ADMIN_USER"

    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" \
        "/home/${ADMIN_USER}/.ssh"

    if [[ -f "/home/${ADMIN_USER}/.ssh/authorized_keys" ]]; then
        chown "$ADMIN_USER:$ADMIN_USER" "/home/${ADMIN_USER}/.ssh/authorized_keys"
        chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
        log "authorized_keys encontrado para ${ADMIN_USER}."
    else
        log "AVISO: authorized_keys não encontrado para ${ADMIN_USER}."
        log "A autenticação por senha NÃO será desabilitada automaticamente."
        DISABLE_SSH_PASSWORD="false"
    fi

    {
        echo "===== ADMIN USER ====="
        id "$ADMIN_USER"
        echo
        echo "===== SUDO GROUP ====="
        getent group sudo || true
        echo
        echo "===== SSH DIRECTORY ====="
        ls -la "/home/${ADMIN_USER}/.ssh"
    } > "${HARDENING_DIR}/admin-user.txt"
}

configure_ssh() {
    log "Configurando hardening do SSH..."

    local sshd_dropin="/etc/ssh/sshd_config.d/99-linux-hardening.conf"

    cp -a /etc/ssh/sshd_config \
        "${HARDENING_DIR}/sshd_config.before" 2>/dev/null || true

    cat > "$sshd_dropin" <<EOF
# Linux Hardening Lab
# Gerado em $(timestamp)

PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowUsers ${ADMIN_USER}
EOF

    if [[ "$DISABLE_SSH_PASSWORD" == "true" ]]; then
        cat >> "$sshd_dropin" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    else
        cat >> "$sshd_dropin" <<'EOF'
# PasswordAuthentication mantido por segurança/rollback.
PasswordAuthentication yes
EOF
    fi

    chmod 644 "$sshd_dropin"
    cp -a "$sshd_dropin" "${HARDENING_DIR}/sshd_config"

    sshd -t
    systemctl reload ssh

    {
        echo "===== SSH EFFECTIVE CONFIG ====="
        sshd -T | grep -E \
            'permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication|x11forwarding|kbdinteractiveauthentication|allowusers' \
            || true
    } > "${VALIDATION_DIR}/ssh-after.txt"

    log "Hardening SSH aplicado."
}

configure_ufw() {
    log "Configurando UFW..."

    apt-get install -y ufw

    # Regra SSH restrita à origem definida.
    ufw --force delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw --force delete allow from "${SSH_ALLOWED_FROM}" to any port "${SSH_PORT}" proto tcp >/dev/null 2>&1 || true

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow from "${SSH_ALLOWED_FROM}" to any port "${SSH_PORT}" proto tcp \
        comment 'SSH - Linux Hardening Lab'

    ufw --force enable

    ufw status verbose > "${HARDENING_DIR}/ufw-rules.txt"

    log "UFW ativo. SSH permitido somente de ${SSH_ALLOWED_FROM}."
}

disable_unnecessary_services() {
    log "Analisando serviços..."

    # Não desabilita serviços automaticamente.
    # Isso evita quebrar componentes necessários ao ambiente.
    {
        echo "===== SERVIÇOS ATIVOS APÓS HARDENING ====="
        systemctl --type=service --state=running
        echo
        echo "===== PORTAS ====="
        ss -tulpn
        echo
        echo "NOTA:"
        echo "Serviços não foram desabilitados automaticamente."
        echo "Cada serviço deve ser avaliado antes de executar:"
        echo "  systemctl disable --now NOME_DO_SERVICO"
    } > "${HARDENING_DIR}/services-review.txt"

    log "Lista de serviços preparada para revisão manual."
}

configure_fail2ban() {
    log "Instalando/configurando Fail2ban..."

    apt-get install -y fail2ban

    cat > /etc/fail2ban/jail.d/sshd-hardening.conf <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 3
findtime = 10m
bantime = 1h
EOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban

    fail2ban-client status > "${VALIDATION_DIR}/fail2ban-after.txt" 2>&1 || true
    fail2ban-client status sshd >> "${VALIDATION_DIR}/fail2ban-after.txt" 2>&1 || true

    log "Fail2ban configurado."
}

configure_auditd() {
    log "Instalando/configurando Auditd..."

    apt-get install -y auditd audispd-plugins

    systemctl enable --now auditd || true

    {
        echo "===== AUDITD STATUS ====="
        systemctl status auditd --no-pager || true
        echo
        echo "===== AUDITCTL STATUS ====="
        auditctl -s || true
        echo
        echo "===== AUDIT RULES ====="
        auditctl -l || true
    } > "${VALIDATION_DIR}/audit-after.txt"

    log "Auditd configurado."
}

configure_sysctl() {
    log "Aplicando hardening básico do kernel..."

    local sysctl_file="/etc/sysctl.d/99-linux-hardening.conf"

    cat > "$sysctl_file" <<'EOF'
# Linux Hardening Lab
# Aplicação de parâmetros básicos de segurança

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1

kernel.randomize_va_space = 2
EOF

    cp -a "$sysctl_file" "${HARDENING_DIR}/sysctl-hardening.conf"

    sysctl --system >/dev/null

    {
        echo "===== SYSCTL VALIDATION ====="
        sysctl net.ipv4.conf.all.accept_redirects
        sysctl net.ipv4.conf.default.accept_redirects
        sysctl net.ipv4.conf.all.send_redirects
        sysctl net.ipv4.conf.all.accept_source_route
        sysctl net.ipv4.conf.default.accept_source_route
        sysctl net.ipv4.conf.all.rp_filter
        sysctl net.ipv4.conf.default.rp_filter
        sysctl net.ipv4.icmp_echo_ignore_broadcasts
        sysctl kernel.randomize_va_space
    } > "${VALIDATION_DIR}/sysctl-after.txt"

    log "Sysctl aplicado."
}

run_validation() {
    log "Executando validação final..."

    {
        echo "===== VALIDATION - $(timestamp) ====="
        echo
        echo "===== HOSTNAME ====="
        hostnamectl
        echo
        echo "===== KERNEL ====="
        uname -a
        echo
        echo "===== NETWORK ====="
        ip addr
        echo
        echo "===== ROUTES ====="
        ip route
        echo
        echo "===== PORTS ====="
        ss -tulpn
        echo
        echo "===== RUNNING SERVICES ====="
        systemctl --type=service --state=running
        echo
        echo "===== ADMIN USER ====="
        id "$ADMIN_USER"
        echo
        echo "===== UID 0 ====="
        awk -F: '$3 == 0 {print $1}' /etc/passwd
        echo
        echo "===== FIREWALL ====="
        ufw status verbose
        echo
        echo "===== SSH ====="
        sshd -T | grep -E \
            'permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication|x11forwarding|kbdinteractiveauthentication|allowusers' \
            || true
        echo
        echo "===== FAIL2BAN ====="
        fail2ban-client status || true
        echo
        echo "===== AUDITD ====="
        auditctl -s || true
        echo
        echo "===== SYSCTL ====="
        sysctl net.ipv4.conf.all.accept_redirects
        sysctl net.ipv4.conf.all.send_redirects
        sysctl net.ipv4.conf.all.accept_source_route
        sysctl net.ipv4.conf.all.rp_filter
        sysctl kernel.randomize_va_space
        echo
        echo "===== UPDATES ====="
        apt list --upgradable 2>/dev/null || true
    } > "${VALIDATION_DIR}/validation.txt"

    ss -tulpn > "${VALIDATION_DIR}/ports-after.txt"
    systemctl --type=service --state=running > "${VALIDATION_DIR}/services-after.txt"
    ufw status verbose > "${VALIDATION_DIR}/firewall-after.txt"
    apt list --upgradable 2>/dev/null > "${VALIDATION_DIR}/updates-after.txt" || true

    if command -v nmap >/dev/null 2>&1; then
        nmap -sV 127.0.0.1 > "${VALIDATION_DIR}/nmap-after.txt" 2>&1 || true
    fi

    log "Validação final concluída."
}

generate_summary() {
    local report="${REPORT_DIR}/hardening-report.md"

    cat > "$report" <<EOF
# Relatório — Linux Server Hardening

## 1. Identificação

- **Data:** $(date '+%Y-%m-%d %H:%M:%S')
- **Hostname:** $(hostname)
- **Sistema:** $(. /etc/os-release && echo "\${PRETTY_NAME}")
- **Kernel:** $(uname -r)
- **Usuário administrativo:** ${ADMIN_USER}
- **Porta SSH:** ${SSH_PORT}
- **Origem permitida para SSH:** ${SSH_ALLOWED_FROM}

## 2. Objetivo

Aplicar controles básicos de hardening em um servidor Ubuntu Linux,
reduzindo a superfície de ataque e produzindo evidências antes/depois.

## 3. Controles implementados

- [x] Atualização do sistema
- [x] Atualizações automáticas
- [x] Usuário administrativo dedicado
- [x] SSH com chave pública
- [x] Root bloqueado via SSH
- [x] Limitação de tentativas SSH
- [x] X11 Forwarding desabilitado
- [x] UFW habilitado
- [x] SSH restrito à origem definida
- [x] Fail2ban
- [x] Auditd
- [x] Sysctl
- [x] Evidências de validação

## 4. Evidências

Consulte:

- \`01-baseline/baseline.txt\`
- \`02-hardening/sshd_config\`
- \`02-hardening/ufw-rules.txt\`
- \`02-hardening/sysctl-hardening.conf\`
- \`03-validation/validation.txt\`
- \`03-validation/ports-after.txt\`
- \`03-validation/services-after.txt\`
- \`03-validation/ssh-after.txt\`
- \`03-validation/firewall-after.txt\`
- \`03-validation/fail2ban-after.txt\`
- \`03-validation/audit-after.txt\`
- \`03-validation/sysctl-after.txt\`

## 5. Riscos residuais

Este script implementa controles básicos. Recomenda-se complementar o
laboratório com:

- Lynis;
- CIS Benchmark;
- OpenSCAP;
- Scanner de vulnerabilidades;
- Wazuh/SIEM;
- Centralização de logs;
- Gestão de patches;
- File Integrity Monitoring;
- Backup e teste de restauração.

## 6. Rollback

Antes da execução foi recomendado criar snapshot da VM.

Para desfazer manualmente os principais arquivos:

\`\`\`bash
rm -f /etc/ssh/sshd_config.d/99-linux-hardening.conf
rm -f /etc/sysctl.d/99-linux-hardening.conf
systemctl reload ssh
sysctl --system
\`\`\`

As regras do UFW devem ser revisadas antes de qualquer rollback para
garantir que o acesso administrativo continue disponível.

## 7. Conclusão

O laboratório implementou um ciclo básico de:

**Baseline → Hardening → Validação → Evidências → Relatório**
EOF

    log "Relatório inicial gerado em ${report}"
}

final_checks() {
    log "Executando verificações finais..."

    local errors=0

    if ! systemctl is-active --quiet ssh; then
        log "ERRO: SSH não está ativo."
        errors=$((errors + 1))
    fi

    if ! ufw status | grep -q "Status: active"; then
        log "ERRO: UFW não está ativo."
        errors=$((errors + 1))
    fi

    if ! systemctl is-active --quiet fail2ban; then
        log "AVISO: Fail2ban não está ativo."
    fi

    if id "$ADMIN_USER" >/dev/null 2>&1; then
        log "OK: usuário ${ADMIN_USER} existe."
    else
        log "ERRO: usuário ${ADMIN_USER} não existe."
        errors=$((errors + 1))
    fi

    if [[ "$errors" -gt 0 ]]; then
        log "Validação final encontrou ${errors} erro(s)."
        return 1
    fi

    log "Verificações finais concluídas sem erros críticos."
}

main() {
    require_root
    check_os
    prepare_dirs
    snapshot_warning
    confirm_start

    log "=== INÍCIO DO HARDENING ==="

    run_baseline
    update_system
    create_admin_user
    configure_ssh
    configure_ufw
    disable_unnecessary_services
    configure_fail2ban
    configure_auditd
    configure_sysctl
    run_validation
    generate_summary
    final_checks

    log "=== HARDENING CONCLUÍDO ==="

    echo
    echo "=============================================================="
    echo " LABORATÓRIO CONCLUÍDO"
    echo "=============================================================="
    echo
    echo "Evidências:"
    echo "  ${LAB_ROOT}/01-baseline/"
    echo "  ${LAB_ROOT}/02-hardening/"
    echo "  ${LAB_ROOT}/03-validation/"
    echo "  ${LAB_ROOT}/04-report/"
    echo
    echo "Relatório:"
    echo "  ${REPORT_DIR}/hardening-report.md"
    echo
    echo "IMPORTANTE:"
    echo "  Teste uma NOVA sessão SSH antes de encerrar a sessão atual."
    echo "=============================================================="
}

main "$@"
