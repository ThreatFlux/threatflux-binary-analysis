#!/bin/bash
# Script to install git hooks for the project

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook to run make all before committing
# This ensures all tests, linting, and formatting checks pass

set -e

echo "🔍 Running pre-commit checks with 'make all'..."
echo ""

# Save current directory
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Run make all
if ! make all; then
    echo ""
    echo "❌ Pre-commit check failed!"
    echo "Please fix the issues above before committing."
    echo ""
    echo "Tip: You can bypass this hook with 'git commit --no-verify' if needed."
    exit 1
fi

echo ""
echo "✅ All pre-commit checks passed!"
echo ""

exit 0
EOF

# Make the hook executable
chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Git hooks installed successfully!"
echo ""
echo "The pre-commit hook will now run 'make all' before each commit."
echo "You can bypass it with 'git commit --no-verify' if needed."