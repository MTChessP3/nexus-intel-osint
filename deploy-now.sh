#!/bin/bash

# ╔══════════════════════════════════════════════════════════╗
# ║  NEXUS INTEL - DEPLOYMENT SCRIPT                          ║
# ║  Ejecuta esto en tu terminal y sigue las instrucciones    ║
# ╚══════════════════════════════════════════════════════════╝

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🛡️  NEXUS INTEL - OSINT Platform Deployment           ║"
echo "║  This will deploy your platform to GitHub + Vercel      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install it first:"
    echo "   https://git-scm.com/downloads"
    exit 1
fi

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install it first:"
    echo "   https://nodejs.org/"
    exit 1
fi

echo "✅ Prerequisites OK!"
echo ""

# ============================================
# STEP 1: Create project directory
# ============================================
echo "📁 Step 1/4: Setting up project..."
echo ""

PROJECT_DIR="$HOME/nexus-intel-platform"

if [ -d "$PROJECT_DIR" ]; then
    echo "   Project directory already exists. Updating..."
else
    mkdir -p "$PROJECT_DIR"
    echo "   Created: $PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# Check if it's already a git repo
if [ ! -d ".git" ]; then
    git init
    echo "   Initialized git repository"
fi

echo ""

# ============================================
# STEP 2: Install dependencies and build
# ============================================
echo "📦 Step 2/4: Installing dependencies..."
echo ""

if [ ! -d "node_modules" ]; then
    # Create package.json if not exists
    if [ ! -f "package.json" ]; then
        cat > package.json << 'PKGJSON'
{
  "name": "nexus-intel-osint",
  "version": "3.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev --turbopack",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "^16.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "lucide-react": "^0.460.0",
    "class-variance-authority": "^0.7.1",
    "clsx": "^2.1.1",
    "tailwind-merge": "^2.6.0",
    "@radix-ui/react-slot": "^1.1.1",
    "@radix-ui/react-dialog": "^1.1.4",
    "@radix-ui/react-dropdown-menu": "^2.1.4",
    "@radix-ui/react-select": "^2.1.4",
    "@radix-ui/react-tabs": "^1.1.2",
    "@radix-ui/react-progress": "^1.1.1",
    "@radix-ui/react-separator": "^1.1.1",
    "@radix-ui/react-scroll-area": "^1.2.2",
    "@radix-ui/react-tooltip": "^1.1.6",
    "@radix-ui/react-badge": "^1.0.2",
    "@radix-ui/react-avatar": "^1.1.2",
    "@radix-ui/react-popover": "^1.1.4"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "@types/node": "^22.10.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "tailwindcss": "^4.0.0",
    "@tailwindcss/postcss": "^4.0.0",
    "postcss": "^8.4.49",
    "eslint": "^9.17.0",
    "eslint-config-next": "^16.0.0"
  }
}
PKGJSON
        echo "   Created package.json"
    fi
    
    npm install
    echo "   ✅ Dependencies installed"
else
    echo "   Dependencies already installed"
fi

echo ""

# ============================================
# STEP 3: Push to GitHub
# ============================================
echo "🐙 Step 3/4: Push to GitHub..."
echo ""

# Ask for GitHub username
read -p "   Enter your GitHub username: " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo "   ❌ Username cannot be empty"
    exit 1
fi

REPO_NAME="nexus-intel-osint"
REPO_URL="https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"

# Check if remote exists
if git remote get-url origin &>/dev/null; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

echo "   Repository will be: $REPO_URL"
echo ""

# Stage all files
git add -A || true

# Commit if there are changes
if git diff --cached --quiet; then
    echo "   No changes to commit"
else
    git commit -m "🛡️ Add NEXUS INTEL OSINT & Threat Intelligence Platform" || echo "   (Nothing to commit)"
fi

echo ""
echo "   ⚡  Now we'll create the repo on GitHub and push..."
echo ""
echo "   If prompted, enter your GitHub credentials..."
echo ""

# Try to create repo using gh or give manual instructions
if command -v gh &> /dev/null && gh auth status &>/dev/null 2>&1; then
    gh repo create "$REPO_NAME" --public --source=. --push --description "🛡️ Professional OSINT & Threat Intelligence Platform" 2>/dev/null || git push -u origin main --force
else
    echo "   ⚠️  GitHub CLI not authenticated. Manual steps:"
    echo ""
    echo "   1) Go to: https://github.com/new"
    echo "   2) Repository name: $REPO_NAME"
    echo "   3) Select **PUBLIC**"
    echo "   4) ❌ DON'T initialize with README"
    echo "   5) Click **Create repository**"
    echo ""
    read -p "   Press ENTER after creating the repository on GitHub..."
    
    git push -u origin main --force
fi

echo ""
echo "   ✅ Code pushed to GitHub!"
echo "   🔗 https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo ""

# ============================================
# STEP 4: Deploy to Vercel
# ============================================
echo "🚀 Step 4/4: Deploy to Vercel..."
echo ""

if command -v vercel &> /dev/null && vercel whoami &>/dev/null 2>&1; then
    echo "   Vercel CLI found and authenticated. Deploying..."
    vercel --yes --prod
    echo ""
    echo "   ✅ Deployed to Vercel!"
else
    echo "   📋 To deploy to Vercel, you have TWO options:"
    echo ""
    echo "   ┌─────────────────────────────────────────────────┐"
    echo "   │ OPTION A: Use Vercel Website (EASIEST)          │"
    echo "   ├─────────────────────────────────────────────────┤"
    echo "   │ 1. Go to: https://vercel.com/new                │"
    echo "   │ 2. Click 'Import Git Repository'               │"
    echo "   │ 3. Select: $GITHUB_USERNAME/$REPO_NAME       │"
    echo "   │ 4. Click 'Deploy'                              │"
    echo "   │ 5. Wait ~2 minutes                             │"
    echo "   │ 6. 🎉 Your platform is LIVE!                   │"
    echo "   └─────────────────────────────────────────────────┘"
    echo ""
    echo "   ┌─────────────────────────────────────────────────┐"
    echo "   │ OPTION B: Use Vercel CLI                       │"
    echo "   ├─────────────────────────────────────────────────┤"
    echo "   │ Run these commands in your terminal:            │"
    echo "   │                                                 │"
    echo "   │   npm i -g vercel                               │"
    echo "   │   cd $PROJECT_DIR                          │"
    echo "   │   vercel login                                  │"
    echo "   │   vercel --yes --prod                           │"
    echo "   └─────────────────────────────────────────────────┘"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🎉 DEPLOYMENT COMPLETE!                               ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Your platform URLs:                                 ║"
echo "║  • GitHub: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo "║  • Vercel:  https://$REPO_NAME.vercel.app (after deploy)  ║"
echo "║                                                      ║"
echo "║  Test these features when live:                      ║"
echo "║  • IP Intel → Enter: 8.8.8.8                         ║"
echo "║  • CVE Search → Enter: CVE-2024                      ║"
echo "║  • Reports → Click 'Threat Assessment'              ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
