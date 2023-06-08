munged:  $(wildcard ../src/*.sol) applyHarness.patch
	@rm -rf munged
	@cp -r ../src munged
	@patch -p0 -d munged < applyHarness.patch

record:
	diff -ruN ../src munged | sed 's+\.\./src/++g' | sed 's+munged/++g' > applyHarness.patch

.PHONY: record
