PACKAGE := iamvpnlibrary
.DEFAULT: test
.PHONY: all test coverage coveragereport pep8 pylint rpm clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -f -s test

all: test

test:
	python -B $(TEST_FLAGS_FOR_SUITE)

coverage:
	coverage run $(TEST_FLAGS_FOR_SUITE)

coveragereport:
	coverage report -m $(PACKAGE)/*.py test/*.py

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./* -path ./test -prune -o -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,superfluous-parens --rcfile=/dev/null {} \;
	@find ./test -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,protected-access,locally-disabled --rcfile=/dev/null {} \;
# useless-object-inheritance can be fixed once we drop py2 support

rpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

clean:
	rm -f $(PACKAGE)/*.pyc test/*.pyc
	rm -rf build $(PACKAGE).egg-info
