#!/bin/bash
set -e

echo "==================================="
echo "Setting up Lockbox development environment..."
echo "==================================="

# Install Python dependencies
echo "Installing Python dependencies with Poetry..."
poetry install

# Set up pre-commit hooks
echo "Setting up pre-commit hooks..."
poetry run pre-commit install

# Create sample signing key for development if it doesn't exist
if [ ! -f "signing_key.txt" ]; then
    echo "Creating sample signing_key.txt for development..."
    echo "dev_secret_key_$(date +%s)" > signing_key.txt
    echo "⚠️  Generated sample signing_key.txt - DO NOT use in production!"
fi

echo ""
echo "==================================="
echo "✓ Setup complete!"
echo "==================================="
echo ""
echo "Verifying Claude Code installation..."
if command -v claude &> /dev/null; then
    claude --version
    echo "✓ Claude Code is ready to use!"
else
    echo "⚠️  Claude Code not found in PATH"
fi
echo ""
echo "Quick start:"
echo "  1. Start server: gunicorn lockbox.app:app --preload"
echo "  2. Run tests:    poetry run pytest"
echo "  3. Type check:   poetry run pyright"
echo "  4. Use Claude:   claude"
echo ""
echo "Environment variables needed:"
echo "  export LOCKBOX_SIGNING_KEY_FILE=signing_key.txt"
echo "  export LOCKBOX_CONFIG_PATH=sample_config.json"
echo ""
echo "Happy coding!"
echo ""
