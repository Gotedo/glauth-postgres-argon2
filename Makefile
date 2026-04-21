# ================================================
# Argon2-Postgres plugin Makefile
# ================================================

# Add this if you ever build glauth itself in debug mode:
# TRIM_FLAGS += -gcflags='all=-N -l'

# Default to the CURRENT host OS and architecture
PLUGIN_OS   ?= $(shell go env GOOS)
PLUGIN_ARCH ?= $(shell go env GOARCH)
PLUGIN_NAME  = argon2-postgres

OUT_DIR = bin/$(PLUGIN_OS)_$(PLUGIN_ARCH)

# Official-style flags (same as glauth-postgres)
TRIM_FLAGS ?= -trimpath
BUILD_VARS ?=

.PHONY: plugin plugin_linux_amd64 plugin_linux_arm64 plugin_darwin_amd64 plugin_darwin_arm64 release

plugin: $(OUT_DIR)/$(PLUGIN_NAME).so

$(OUT_DIR)/$(PLUGIN_NAME).so: *.go
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=1 GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) \
	go build \
		${TRIM_FLAGS} \
		-ldflags "${BUILD_VARS}" \
		-buildmode=plugin \
		-o $@ *.go

plugin_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 $(MAKE) plugin

plugin_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 $(MAKE) plugin

plugin_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 $(MAKE) plugin

plugin_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 $(MAKE) plugin

release:
	@echo "=== Building Argon2-Postgres plugin for all platforms ==="
	@$(MAKE) plugin_linux_amd64
	@$(MAKE) plugin_linux_arm64
	@$(MAKE) plugin_darwin_amd64
	@$(MAKE) plugin_darwin_arm64
	@echo "✅ Done. Plugins are in ./bin/"

clean:
	rm -rf bin/
	@echo "✅ Cleaned build artifacts"