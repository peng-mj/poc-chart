#!/bin/bash

# Build script for pqc-chart-tool - Multi-platform build
# Supports: Linux/Windows/macOS + amd64/arm64
# Usage: ./build.sh [--upx] [--version VERSION]

set -e

# Parse arguments
USE_UPX=false
for arg in "$@"; do
    case $arg in
        --upx)
            USE_UPX=true
            shift
            ;;
        --version=*)
            VERSION="${arg#*=}"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build configuration
APP_NAME="pqc-chart-tool"
OUTPUT_DIR="output"
VERSION="${VERSION:-dev}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-X main.version=$VERSION -X main.buildTime=$BUILD_TIME"

# Check if upx is installed
check_upx() {
    if command -v upx &> /dev/null; then
        UPX_VERSION=$(upx --version | head -n1)
        echo -e "${GREEN}✓ UPX found: ${UPX_VERSION}${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ UPX not found, skipping compression${NC}"
        return 1
    fi
}

# Platforms to build
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

# Create output directory
echo -e "${GREEN}Creating output directory...${NC}"
mkdir -p "$OUTPUT_DIR"

# Clean output directory
echo -e "${YELLOW}Cleaning output directory...${NC}"
rm -f "${OUTPUT_DIR}/${APP_NAME}"*

# Build function
build_platform() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT_NAME="${APP_NAME}"

    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${APP_NAME}.exe"
    fi

    # Create platform-specific subdirectory
    PLATFORM_DIR="${OUTPUT_DIR}/${GOOS}-${GOARCH}"
    mkdir -p "$PLATFORM_DIR"

    echo -e "${GREEN}Building for ${GOOS}/${GOARCH}...${NC}"

    # Set environment variables and build
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "$LDFLAGS" \
        -o "${PLATFORM_DIR}/${OUTPUT_NAME}" \
        ./cmd/pqc-chart-tool

    if [ $? -eq 0 ]; then
        # Compress with UPX if enabled
        if [ "$USE_UPX" = true ]; then
            if check_upx; then
                echo -e "${YELLOW}  Compressing with UPX -5...${NC}"
                upx -5 "${PLATFORM_DIR}/${OUTPUT_NAME}"
                if [ $? -eq 0 ]; then
                    COMPRESSED_SIZE=$(du -h "${PLATFORM_DIR}/${OUTPUT_NAME}" | cut -f1)
                    echo -e "${GREEN}  Compressed size: ${COMPRESSED_SIZE}${NC}"
                else
                    echo -e "${YELLOW}  ⚠ UPX compression failed, using uncompressed binary${NC}"
                fi
            fi
        fi

        # Create tarball for all platforms
        tar -czf "${OUTPUT_DIR}/${APP_NAME}-${GOOS}-${GOARCH}.tar.gz" \
            -C "$PLATFORM_DIR" "$OUTPUT_NAME"
        echo -e "${GREEN}✓ Created: ${OUTPUT_DIR}/${APP_NAME}-${GOOS}-${GOARCH}.tar.gz${NC}"

        # Display binary size
        BINARY_SIZE=$(du -h "${PLATFORM_DIR}/${OUTPUT_NAME}" | cut -f1)
        echo -e "${GREEN}  Binary size: ${BINARY_SIZE}${NC}"
    else
        echo -e "${RED}✗ Failed to build for ${GOOS}/${GOARCH}${NC}"
        return 1
    fi
}

# Main build process
echo -e "${GREEN}======================================"
echo -e "Building ${APP_NAME} v${VERSION}"
echo -e "======================================${NC}"

# Build for each platform
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -ra PARTS <<< "$platform"
    GOOS="${PARTS[0]}"
    GOARCH="${PARTS[1]}"
    build_platform "$GOOS" "$GOARCH"
done

# Create checksums
echo -e "${YELLOW}Creating checksums...${NC}"
cd "$OUTPUT_DIR"
sha256sum *.tar.gz 2>/dev/null > SHA256SUMS.txt || echo "No archives to checksum"
cd ..

# Summary
echo -e "${GREEN}======================================"
echo -e "Build completed successfully!"
echo -e "======================================${NC}"
echo -e "${YELLOW}Output directory: ${OUTPUT_DIR}/${NC}"
echo -e "${YELLOW}Built versions:${NC}"

for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -ra PARTS <<< "$platform"
    GOOS="${PARTS[0]}"
    GOARCH="${PARTS[1]}"

    if [ -f "${OUTPUT_DIR}/${APP_NAME}-${GOOS}-${GOARCH}.tar.gz" ]; then
        echo -e "  ${GREEN}✓${NC} ${GOOS}/${GOARCH}"
    fi
done

echo -e "\n${YELLOW}Usage:${NC}"
echo -e "  tar -xzf ${APP_NAME}-<platform>-<arch>.tar.gz"
echo -e "\n${YELLOW}Installation:${NC}"
echo -e "  sudo cp ${OUTPUT_DIR}/linux-amd64/${APP_NAME} /usr/local/bin/"
echo -e "  sudo chmod +x /usr/local/bin/${APP_NAME}"
echo -e "\n${YELLOW}Build options:${NC}"
echo -e "  ./build.sh              # Normal build"
echo -e "  ./build.sh --upx        # Build with UPX compression"
echo -e "  ./build.sh --version=1.0.0 # Set version"