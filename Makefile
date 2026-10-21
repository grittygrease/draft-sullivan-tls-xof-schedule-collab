LIBDIR := lib
-include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update --init
else
ifneq (,$(wildcard $(ID_TEMPLATE_HOME)))
	ln -s "$(ID_TEMPLATE_HOME)" $(LIBDIR)
else
	git clone -q --depth 10 -b main \
	    https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
endif

# Run the DeriveN measurement test, which checks the invocation and
# permutation counts the draft states for one full handshake.
check:: check-measurements

check-measurements:
	python3 -B -m unittest discover -s tools/pyverify -p test_derive_n.py
.PHONY: check-measurements

# Regenerate the Test Vectors appendix with the Go generator and the
# independent Python verifier in tools/, and require both to match the
# appendix value for value. Also checks the optional Go TLS stack and altkdf-rs
# when installed; see tools/stack/README.md. Needs Go 1.24+ and Python 3.
vectors-check:
	@python3 tools/pyverify/rfc9861_vectors.py
	python3 tools/vectors_check.py
.PHONY: vectors-check

# Real XOF handshakes and exact stock-Go BoGo regression results.
check-stack:
	python3 tools/stack_check.py
.PHONY: check-stack
