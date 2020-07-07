PACKAGE := iamvpnlibrary
.DEFAULT: test
.PHONY: all test coverage coveragereport pep8 pylint rpm rpm2 rpm3 clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -f -s test

PLAIN_PYTHON = $(shell which python 2>/dev/null)
PYTHON3 = $(shell which python3 2>/dev/null)
ifneq (, $(PYTHON3))
  PYTHON_BIN = $(PYTHON3)
  RPM_MAKE_TARGET = rpm3
endif
ifneq (, $(PLAIN_PYTHON))
  PYTHON_BIN = $(PLAIN_PYTHON)
  RPM_MAKE_TARGET = rpm2
endif

COVERAGE2 = $(shell which coverage 2>/dev/null)
COVERAGE3 = $(shell which coverage-3 2>/dev/null)
ifneq (, $(COVERAGE2))
  COVERAGE = $(COVERAGE2)
endif
ifneq (, $(COVERAGE3))
  COVERAGE = $(COVERAGE3)
endif

all: test

test:
	python -B $(TEST_FLAGS_FOR_SUITE)

coverage:
	$(COVERAGE) run $(TEST_FLAGS_FOR_SUITE)
	@rm -rf test/__pycache__
	@rm -f $(PACKAGE)/*.pyc test/*.pyc

coveragereport:
	$(COVERAGE) report -m $(PACKAGE)/*.py test/*.py

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./* -path ./test -prune -o -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,superfluous-parens --rcfile=/dev/null {} \;
	@find ./test -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,protected-access,locally-disabled --rcfile=/dev/null {} \;
# useless-object-inheritance can be fixed once we drop py2 support

rpm:  $(RPM_MAKE_TARGET)

rpm2:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

rpm3:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --python-package-name-prefix python3 --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

clean:
	rm -f $(PACKAGE)/*.pyc test/*.pyc
	rm -rf test/__pycache__
	rm -rf build $(PACKAGE).egg-info
