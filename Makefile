PARALLELISM := $(shell nproc)

.PHONY: all
all: install phpunit

.PHONY: install
install: vendor/composer/installed.json

vendor/composer/installed.json: composer.json composer.lock
	@composer install $(INSTALL_FLAGS)
	@touch -c composer.json composer.lock vendor/composer/installed.json

.PHONY: phpunit
phpunit:
	@php -d assert.exception=1 -d zend.assertions=1 vendor/bin/phpunit $(PHPUNIT_FLAGS)

