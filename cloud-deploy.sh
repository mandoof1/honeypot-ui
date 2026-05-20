#!/bin/bash
echo "========================================="
echo "  HoneySentinel — Cloud Deploy Helper"
echo "========================================="
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit"
    echo ""
    echo "Now push to GitHub:"
    echo "  git remote add origin https://github.com/YOUR_USERNAME/honeypot-ui.git"
    echo "  git push -u origin main"
    echo ""
fi

# Check if on GitHub
if git remote -v | grep -q github; then
    REPO_URL=$(git remote get-url origin | sed 's/\.git$//')
    echo "Repository: $REPO_URL"
    echo ""
    echo "Step 1: Create Neon database"
    echo "  → https://neon.tech"
    echo "  → Copy connection string"
    echo ""
    echo "Step 2: Deploy to Render"
    echo "  → https://render.com"
    echo "  → New + → Blueprint → Connect this repo"
    echo "  → Set DATABASE_URL to your Neon URL"
    echo ""
    echo "Step 3: Deploy frontend to Vercel"
    echo "  → https://vercel.com"
    echo "  → New Project → Import this repo"
    echo "  → Set VITE_API_URL to your Render API URL"
    echo ""
    echo "Step 4: Seed database"
    echo "  → Render Dashboard → Shell → Run seed script"
    echo ""
    echo "See DEPLOY.md for detailed instructions."
else
    echo "Push your code to GitHub first, then run this script again."
fi
