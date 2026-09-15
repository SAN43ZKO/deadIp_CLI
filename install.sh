#!/usr/bin/env bash
# install.sh — установщик deadip (standalone binary)
set -euo pipefail

REPO="your-user/deadip"
BIN_NAME="deadip"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"
VERIFY_SHA="${VERIFY_SHA:-1}"     # 0 — отключить проверку

# --- определяем платформу ---
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
    Linux)  os="linux"  ;;
    Darwin) os="darwin" ;;
    *) echo "Неподдерживаемая ОС: $os (для Windows используйте WSL)" >&2; exit 1 ;;
esac

case "$arch" in
    x86_64|amd64)  arch="x86_64"  ;;
    arm64|aarch64) arch="arm64"   ;;
    *) echo "Неподдерживаемая архитектура: $arch" >&2; exit 1 ;;
esac

asset="${BIN_NAME}-${os}-${arch}"

# --- URL релиза ---
if [[ "$VERSION" == "latest" ]]; then
    base="https://github.com/${REPO}/releases/latest/download"
else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
fi
url="${base}/${asset}"

echo "→ Скачиваю $asset"
mkdir -p "$INSTALL_DIR"
tmp="$(mktemp)"
if ! curl -fsSL "$url" -o "$tmp"; then
    echo "Не удалось скачать: $url" >&2
    exit 1
fi

# --- проверка SHA256 (если есть SHA256SUMS в релизе) ---
if [[ "$VERIFY_SHA" == "1" ]]; then
    sums="$(mktemp)"
    if curl -fsSL "${base}/SHA256SUMS" -o "$sums" 2>/dev/null; then
        expected="$(grep " ${asset}\$" "$sums" | awk '{print $1}')"
        if [[ -n "$expected" ]]; then
            if command -v sha256sum >/dev/null; then
                actual="$(sha256sum "$tmp" | awk '{print $1}')"
            else
                actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
            fi
            if [[ "$expected" != "$actual" ]]; then
                echo "SHA256 не совпал: ожидалось $expected, получили $actual" >&2
                rm -f "$tmp" "$sums"
                exit 1
            fi
            echo "✓ SHA256 совпал"
        fi
    fi
    rm -f "$sums"
fi

chmod +x "$tmp"
mv "$tmp" "${INSTALL_DIR}/${BIN_NAME}"
echo "✓ Установлено: ${INSTALL_DIR}/${BIN_NAME}"

# --- PATH ---
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    shell_rc="$HOME/.bashrc"
    [[ "${SHELL:-}" == */zsh ]] && shell_rc="$HOME/.zshrc"
    if ! grep -qF "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
        echo "→ PATH обновлён: $shell_rc (перезайдите в шелл)"
    fi
fi

# --- опциональные системные зависимости ---
need_mtr=1
if command -v mtr >/dev/null 2>&1 || command -v traceroute >/dev/null 2>&1; then
    need_mtr=0
fi

if [[ $need_mtr -eq 1 ]]; then
    echo
    echo "Для полной диагностики (слой 4) рекомендуется установить:"
    if [[ "$os" == "linux" ]]; then
        if command -v apt >/dev/null; then
            echo "  sudo apt install mtr-tiny traceroute"
        elif command -v dnf >/dev/null; then
            echo "  sudo dnf install mtr traceroute"
        elif command -v pacman >/dev/null; then
            echo "  sudo pacman -S mtr traceroute"
        fi
    else
        echo "  brew install mtr"
    fi
fi

# --- опциональные capabilities (Linux) ---
if [[ "$os" == "linux" ]] && command -v setcap >/dev/null; then
    for bin in mtr traceroute; do
        p="$(command -v "$bin" 2>/dev/null || true)"
        [[ -z "$p" ]] && continue
        real="$(readlink -f "$p")"
        if ! getcap "$real" 2>/dev/null | grep -q cap_net_raw; then
            echo "→ Для TCP-traceroute без sudo один раз выполните:"
            echo "    sudo setcap cap_net_raw,cap_net_admin+eip $real"
        fi
    done
fi

echo
echo "Проверка:"
"${INSTALL_DIR}/${BIN_NAME}" --version
echo "Запуск:  ${BIN_NAME} --target <IP>"
