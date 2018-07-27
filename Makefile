PACKAGE := iamvpnlibrary
.DEFAULT: test
.PHONY: clean all test pep8 pylint

all: test

test:
	python -B -m unittest discover -f -s test

pep8:
	@find . -type f -name '*.py' -exec pep8 {} \;

pylint:
	@find . -type f -name '*.py' -exec pylint -r no --disable=locally-disabled {} \;

rpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

clean:
	rm -f *.pyc test/*.pyc
	rm -rf build $(PACKAGE).egg-info
