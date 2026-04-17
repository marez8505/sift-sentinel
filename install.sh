#!/usr/bin/env bash
# install.sh — SIFT Sentinel installer
# Installs the autonomous IR agent extension on top of Protocol SIFT.
#
# Usage:
#   bash install.sh                 # standard install
#   bash install.sh --no-weasyprint # skip PDF library install
#   bash install.sh --uninstall     # remove installed files
#
# Requires: SANS SIFT Workstation, Claude Code CLI, Python 3.10+, Anthropic API key.

set -euo pipefail

# ---- Colors ----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---- Defaults --------------------------------------------------------------
INSTALL_WEASYPRINT=true
UNINSTALL=false
CLAUDE_DIR="${HOME}/.claude"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ---- Parse args ------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --no-weasyprint) INSTALL_WEASYPRINT=false ;;
    --uninstall)     UNINSTALL=true ;;
    --help|-h)
      echo "Usage: bash install.sh [--no-weasyprint] [--uninstall]"
      exit 0 ;;
  esac
done

# ---- Uninstall -------------------------------------------------------------
if [[ "$UNINSTALL" == "true" ]]; then
  info "Uninstalling SIFT Sentinel..."
  rm -f "${CLAUDE_DIR}/CLAUDE.md"
  rm -f "${CLAUDE_DIR}/settings.json"
  rm -rf "${CLAUDE_DIR}/mcp_server"
  rm -rf "${CLAUDE_DIR}/agent"
  rm -rf "${CLAUDE_DIR}/skills"
  rm -rf "${CLAUDE_DIR}/case-templates"
  rm -rf "${CLAUDE_DIR}/analysis-scripts"
  success "Uninstalled. Backups remain at ${CLAUDE_DIR}/*.bak-*"
  exit 0
fi

# ============================================================================
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         SIFT Sentinel — Autonomous IR Agent Installer       ║"
echo "║         SANS Find Evil! Hackathon Submission                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ---- Preflight checks ------------------------------------------------------
info "Checking prerequisites..."

# Python 3.10+
PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
  error "python3 not found. Install Python 3.10+ first."
  exit 1
fi
PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [[ "${PY_VER%%.*}" -lt 3 ]] || { [[ "${PY_VER%%.*}" -eq 3 ]] && [[ "${PY_VER##*.}" -lt 10 ]]; }; then
  error "Python 3.10+ required, found $PY_VER"
  exit 1
fi
success "Python $PY_VER"

# Claude Code CLI
if ! command -v claude &>/dev/null; then
  warn "Claude Code CLI not found. Install with: npm install -g @anthropic-ai/claude-code"
  warn "Continuing install — you must install Claude Code before running the agent."
else
  success "Claude Code CLI: $(claude --version 2>/dev/null || echo 'installed')"
fi

# SIFT tools
SIFT_MISSING=()
[[ -f "/opt/volatility3-2.20.0/vol.py" ]]      || SIFT_MISSING+=("Volatility 3")
[[ -d "/opt/zimmermantools" ]]                   || SIFT_MISSING+=("EZ Tools (zimmermantools)")
command -v fls &>/dev/null                       || SIFT_MISSING+=("Sleuth Kit (fls)")
command -v log2timeline.py &>/dev/null           || SIFT_MISSING+=("Plaso (log2timeline.py)")
if [[ ${#SIFT_MISSING[@]} -gt 0 ]]; then
  warn "The following SIFT tools are not found — install the full SIFT Workstation OVA:"
  for tool in "${SIFT_MISSING[@]}"; do
    echo "  - $tool"
  done
else
  success "SIFT tool suite detected"
fi

# ---- Create ~/.claude directory structure ----------------------------------
info "Creating ~/.claude directory structure..."
mkdir -p \
  "${CLAUDE_DIR}" \
  "${CLAUDE_DIR}/mcp_server" \
  "${CLAUDE_DIR}/agent" \
  "${CLAUDE_DIR}/skills/memory-analysis" \
  "${CLAUDE_DIR}/skills/plaso-timeline" \
  "${CLAUDE_DIR}/skills/sleuthkit" \
  "${CLAUDE_DIR}/skills/windows-artifacts" \
  "${CLAUDE_DIR}/skills/yara-hunting" \
  "${CLAUDE_DIR}/case-templates" \
  "${CLAUDE_DIR}/analysis-scripts" \
  "${CLAUDE_DIR}/yara-rules"

# ---- Backup existing files -------------------------------------------------
backup_if_exists() {
  local target="$1"
  if [[ -e "$target" ]]; then
    local bak="${target}.bak-${TIMESTAMP}"
    cp -r "$target" "$bak"
    info "Backed up existing $(basename "$target") → $(basename "$bak")"
  fi
}

backup_if_exists "${CLAUDE_DIR}/CLAUDE.md"
backup_if_exists "${CLAUDE_DIR}/settings.json"

# ---- Install global config -------------------------------------------------
info "Installing global CLAUDE.md and settings.json..."
cp "${REPO_DIR}/global/CLAUDE.md"       "${CLAUDE_DIR}/CLAUDE.md"
cp "${REPO_DIR}/global/settings.json"   "${CLAUDE_DIR}/settings.json"
success "Global config installed"

# ---- Install MCP server ----------------------------------------------------
info "Installing MCP server..."
cp "${REPO_DIR}/mcp_server/server.py"       "${CLAUDE_DIR}/mcp_server/server.py"
cp "${REPO_DIR}/mcp_server/__init__.py"     "${CLAUDE_DIR}/mcp_server/__init__.py"
cp "${REPO_DIR}/mcp_server/requirements.txt" "${CLAUDE_DIR}/mcp_server/requirements.txt"

# Install MCP Python package
info "Installing MCP Python package..."
if "$PYTHON" -m pip install --quiet "mcp[cli]>=1.0.0" "typing-extensions>=4.0.0" 2>/dev/null; then
  success "MCP package installed"
else
  warn "pip install failed — try manually: pip3 install 'mcp[cli]>=1.0.0'"
fi

success "MCP server installed at ${CLAUDE_DIR}/mcp_server/server.py"

# ---- Install agent orchestrator --------------------------------------------
info "Installing agent orchestrator..."
cp "${REPO_DIR}/agent/orchestrator.py"      "${CLAUDE_DIR}/agent/orchestrator.py"
cp "${REPO_DIR}/agent/triage_sequences.py"  "${CLAUDE_DIR}/agent/triage_sequences.py"
cp "${REPO_DIR}/agent/report_generator.py"  "${CLAUDE_DIR}/agent/report_generator.py"
cp "${REPO_DIR}/agent/__init__.py"          "${CLAUDE_DIR}/agent/__init__.py"
success "Agent orchestrator installed"

# ---- Install skills (from Protocol SIFT baseline + our extensions) ---------
info "Installing skill files..."
# Copy upstream Protocol SIFT skills if repo is present
PSIFT_DIR="${REPO_DIR}/../protocol-sift"
if [[ -d "$PSIFT_DIR/skills" ]]; then
  cp "${PSIFT_DIR}/skills/memory-analysis/SKILL.md"   "${CLAUDE_DIR}/skills/memory-analysis/SKILL.md"
  cp "${PSIFT_DIR}/skills/plaso-timeline/SKILL.md"    "${CLAUDE_DIR}/skills/plaso-timeline/SKILL.md"
  cp "${PSIFT_DIR}/skills/sleuthkit/SKILL.md"         "${CLAUDE_DIR}/skills/sleuthkit/SKILL.md"
  cp "${PSIFT_DIR}/skills/windows-artifacts/SKILL.md" "${CLAUDE_DIR}/skills/windows-artifacts/SKILL.md"
  cp "${PSIFT_DIR}/skills/yara-hunting/SKILL.md"      "${CLAUDE_DIR}/skills/yara-hunting/SKILL.md"
  success "Protocol SIFT skill files installed"
else
  warn "Protocol SIFT skills not found at ${PSIFT_DIR} — install Protocol SIFT first:"
  warn "  curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash"
fi

# ---- Install case template -------------------------------------------------
info "Installing case template..."
cp "${REPO_DIR}/case-templates/CLAUDE.md" "${CLAUDE_DIR}/case-templates/CLAUDE.md"
success "Case template installed"

# ---- Install analysis scripts ----------------------------------------------
info "Installing PDF report generator..."
# Copy Protocol SIFT's generator if available
if [[ -f "${PSIFT_DIR}/analysis-scripts/generate_pdf_report.py" ]]; then
  cp "${PSIFT_DIR}/analysis-scripts/generate_pdf_report.py" \
     "${CLAUDE_DIR}/analysis-scripts/generate_pdf_report.py"
fi

# ---- Install YARA rules ----------------------------------------------------
info "Installing starter YARA ruleset..."
cp "${REPO_DIR}/scripts/yara_rules.yar" "${CLAUDE_DIR}/yara-rules/sift_sentinel.yar"
success "YARA rules installed at ${CLAUDE_DIR}/yara-rules/sift_sentinel.yar"

# ---- WeasyPrint (PDF support) ----------------------------------------------
if [[ "$INSTALL_WEASYPRINT" == "true" ]]; then
  info "Installing WeasyPrint (PDF report generation)..."
  if "$PYTHON" -m pip install --quiet weasyprint 2>/dev/null; then
    success "WeasyPrint installed"
  else
    warn "WeasyPrint install failed — HTML reports will still work, PDFs require WeasyPrint"
    warn "Try: sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 && pip3 install weasyprint"
  fi
fi

# ---- Verify installation ---------------------------------------------------
echo ""
info "Verifying installation..."
VERIFIED=true

check_file() {
  if [[ -f "$1" ]]; then
    success "$2"
  else
    error "Missing: $1"
    VERIFIED=false
  fi
}

check_file "${CLAUDE_DIR}/CLAUDE.md"                        "Global CLAUDE.md"
check_file "${CLAUDE_DIR}/settings.json"                    "settings.json"
check_file "${CLAUDE_DIR}/mcp_server/server.py"             "MCP server"
check_file "${CLAUDE_DIR}/agent/orchestrator.py"            "Agent orchestrator"
check_file "${CLAUDE_DIR}/agent/triage_sequences.py"        "Triage sequences"
check_file "${CLAUDE_DIR}/agent/report_generator.py"        "Report generator"
check_file "${CLAUDE_DIR}/case-templates/CLAUDE.md"         "Case template"
check_file "${CLAUDE_DIR}/yara-rules/sift_sentinel.yar"     "YARA ruleset"

# Verify Python syntax
if "$PYTHON" -m py_compile "${CLAUDE_DIR}/mcp_server/server.py" 2>/dev/null; then
  success "MCP server syntax OK"
else
  error "MCP server has Python syntax errors"
  VERIFIED=false
fi

if "$PYTHON" -m py_compile "${CLAUDE_DIR}/agent/orchestrator.py" 2>/dev/null; then
  success "Orchestrator syntax OK"
else
  error "Orchestrator has Python syntax errors"
  VERIFIED=false
fi

# ---- Summary ---------------------------------------------------------------
echo ""
if [[ "$VERIFIED" == "true" ]]; then
  echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  SIFT Sentinel installed successfully.                      ║${NC}"
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
else
  echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║  Install completed with errors. Check output above.         ║${NC}"
  echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
fi

echo ""
echo "  Installed to:  ${CLAUDE_DIR}/"
echo ""
echo "  Quick start:"
echo "    # Set your Anthropic API key (first-time Claude Code setup)"
echo "    claude  # Run once to configure API key"
echo ""
echo "    # Run autonomous triage against a case"
echo "    python3 ${CLAUDE_DIR}/agent/orchestrator.py \\"
echo "        --case-dir /cases/srl \\"
echo "        --evidence disk:/cases/srl/base-rd01-cdrive.E01 \\"
echo "                   memory:/cases/memory/rd01-memory.img \\"
echo "        --max-iterations 3"
echo ""
echo "    # Or use Claude Code interactively (reads CLAUDE.md automatically)"
echo "    cd /cases/srl && claude"
echo ""
echo "  Docs: see ${REPO_DIR}/docs/ for full architecture, try-it-out, and accuracy reports."
echo ""
