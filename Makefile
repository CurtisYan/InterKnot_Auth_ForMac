APP_NAME = InterKnotAuth
APP_BUNDLE = $(APP_NAME).app
BUILD_DIR = .build

all: bundle

build:
	swift build -c release

bundle: build
	mkdir -p "$(APP_BUNDLE)/Contents/MacOS"
	mkdir -p "$(APP_BUNDLE)/Contents/Resources"
	cp "$(BUILD_DIR)/release/$(APP_NAME)" "$(APP_BUNDLE)/Contents/MacOS/"
	cp Info.plist "$(APP_BUNDLE)/Contents/"
	@if [ -f Resources/Icon.icns ]; then cp Resources/Icon.icns "$(APP_BUNDLE)/Contents/Resources/"; fi
	@echo "Bundle created: $(APP_BUNDLE)"

install: bundle
	cp -R "$(APP_BUNDLE)" /Applications/
	@echo "Installed to /Applications/$(APP_BUNDLE)"

run: bundle
	open "$(APP_BUNDLE)"

clean:
	rm -rf "$(BUILD_DIR)"
	rm -rf "$(APP_BUNDLE)"

.PHONY: all build bundle install run clean
