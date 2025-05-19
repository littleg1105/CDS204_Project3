#!/bin/bash

# Script to run tests and display documentation

echo "🧪 Running tests with documentation..."
echo

# Run tests
python manage.py test --settings=eshop_project.test_settings

echo
echo "📊 Finding latest test documentation..."

# Find the most recent test documentation file
LATEST_DOCS=$(ls -t eshop/tests/test_documentation_*.md 2>/dev/null | head -1)

if [ -z "$LATEST_DOCS" ]; then
    echo "❌ No test documentation found"
else
    echo "✅ Latest documentation: $LATEST_DOCS"
    echo
    echo "Preview:"
    echo "--------"
    head -20 "$LATEST_DOCS"
    echo "..."
    echo
    echo "Full report available at: $LATEST_DOCS"
fi