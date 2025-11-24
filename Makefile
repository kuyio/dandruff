# Makefile for Dandruff Ruby Gem

.PHONY: all test build clean install lint help

# Default target
all: test build

# Run test suite
specs:
	bundle exec rake spec

# Build the gem
build:
	gem build dandruff.gemspec

# Clean build artifacts
clean:
	rm -f *.gem

# Install the gem locally
install: build
	gem install dandruff-*.gem

# Run linting
lint:
	bundle exec rubocop

# Run both specs and linting
test: specs lint

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Run tests and build the gem (default)"
	@echo "  test    - Run both specs and linting"
	@echo "  build   - Build the gem package"
	@echo "  install - Build and install the gem locally"
	@echo "  clean   - Remove built gem files"
	@echo "  specs   - Run the test suite"
	@echo "  lint    - Run RuboCop linting"
	@echo "  help    - Show this help message"