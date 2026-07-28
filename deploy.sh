#!/bin/bash

# NEXUS INTEL - Deployment Script
# This script helps you deploy to GitHub and Vercel

set -e

echo "🛡️  NEXUS INTEL - OSINT Platform Deployment"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${YELLOW}⚠️  $1 is not installed${NC}"
        return 1
    fi
    return 0
}

# Check prerequisites
echo "📋 Checking prerequisites..."
echo ""

HAS_GH=false
HAS_VERCEL=false
HAS_NODE=false

if check_command gh; then
    HAS_GH=true
    echo -e "${GREEN}✓${NC} GitHub CLI installed"
fi

if check_command vercel; then
    HAS_VERCEL=true
    echo -e "${GREEN}✓${NC} Vercel CLI installed"
fi

if check_command node; then
    HAS_NODE=true
    echo -e "${GREEN}✓${NC} Node.js installed"
fi

if check_command git; then
    echo -e "${GREEN}✓${NC} Git installed"
fi

echo ""
echo "🚀 Deployment Options:"
echo ""
echo "1) Deploy to Vercel (Recommended - Easiest)"
echo "2) Push to GitHub (Manual setup required)"
echo "3) Run locally with Docker"
echo "4) Run locally with npm"
echo "5) Exit"
echo ""

read -p "Select option [1-5]: " choice

case $choice in
    1)
        echo ""
        echo "📦 Deploying to Vercel..."
        echo ""
        
        if [ "$HAS_VERCEL" = false ]; then
            echo "Installing Vercel CLI..."
            npm install -g vercel
        fi
        
        # Install dependencies if needed
        if [ ! -d "node_modules" ]; then
            echo "Installing dependencies..."
            npm install
        fi
        
        # Deploy to production
        echo ""
        echo "Starting deployment to Vercel..."
        vercel --yes --prod
        
        echo ""
        echo -e "${GREEN}✅ Deployment complete!${NC}"
        echo "Your platform should now be live on Vercel."
        ;;
        
    2)
        echo ""
        echo "📤 Pushing to GitHub..."
        echo ""
        
        if [ "$HAS_GH" = false ]; then
            echo -e "${YELLOW}GitHub CLI not found. Please install it:${NC}"
            echo "  npm install -g gh"
            echo "  gh auth login"
            exit 1
        fi
        
        # Check if authenticated
        if ! gh auth status &> /dev/null; then
            echo "Please authenticate with GitHub first:"
            echo "  gh auth login"
            exit 1
        fi
        
        REPO_NAME="nexus-intel-osint-platform"
        
        echo "Creating repository: $REPO_NAME ..."
        gh repo create $REPO_NAME \
            --public \
            --description "🛡️ Professional OSINT & Threat Intelligence Platform" \
            --source=. \
            --push \
            || {
                echo "Repository might already exist. Trying to push..."
                git remote add origin "https://github.com/$(gh api user --jq '.login')/$REPO_NAME.git" 2>/dev/null || true
                git push -u origin main
            }
        
        echo ""
        echo -e "${GREEN}✅ Repository created!${NC}"
        echo "🔗 https://github.com/$(gh api user --jq '.login')/$REPO_NAME"
        
        echo ""
        echo "To deploy to Vercel from GitHub:"
        echo "1. Go to https://vercel.com/new"
        echo "2. Import your repository"
        echo "3. Deploy!"
        ;;
        
    3)
        echo ""
        "🐳 Running with Docker..."
        echo ""
        
        if command -v docker &> /dev/null; then
            docker-compose up -d --build
            
            echo ""
            echo -e "${GREEN}✅ Docker container started!${NC}"
            echo "🔗 http://localhost:3000"
            
            echo ""
            echo "To stop: docker-compose down"
            echo "To view logs: docker-compose logs -f"
        else
            echo -e "${RED}❌ Docker not installed${NC}"
            echo "Please install Docker first: https://docs.docker.com/get-docker/"
        fi
        ;;
        
    4)
        echo ""
        "💻 Running locally..."
        echo ""
        
        if [ "$HAS_NODE" = true ]; then
            # Install dependencies if needed
            if [ ! -d "node_modules" ]; then
                echo "Installing dependencies..."
                npm install
            fi
            
            echo "Starting development server..."
            echo ""
            npm run dev
            
            echo ""
            echo -e "${GREEN}✅ Server running!${NC}"
            echo "🔗 http://localhost:3000"
        else
            echo -e "${RED}❌ Node.js not installed${NC}"
            echo "Please install Node.js: https://nodejs.org/"
        fi
        ;;
        
    5)
        echo "👋 Goodbye!"
        exit 0
        ;;
        
    *)
        echo -e "${RED}❌ Invalid option${NC}"
        exit 1
        ;;
esac
