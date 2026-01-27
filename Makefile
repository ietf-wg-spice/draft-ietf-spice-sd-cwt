LIBDIR := lib
DEPS_FILES := .examples.dep
include $(LIBDIR)/main.mk

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

# Check make version (must be 4.0 or higher)
ifeq ($(filter 4.%,$(MAKE_VERSION)),)
    $(error This Makefile requires GNU Make 4.0 or higher. Current version: $(MAKE_VERSION))
endif

.SECONDARY: $(drafts_xml)

includes := examples/issuer_cwt.edn \
            examples/first-disclosure.edn \
            examples/first-disclosure.pretty \
            examples/first-blinded-hash.txt \
            examples/first-redacted.edn \
            examples/chosen-disclosures.edn \
            examples/elided-kbt.edn \
            examples/decoy.edn \
            examples/aead-key.txt \
            examples/aead-claim-array.edn \
            examples/kbt.edn

local-sources := examples/decoy_list.csv \
                 examples/salt_list.csv \
                 examples/sd-cwt.py \
                 examples/enc-disc.py \
                 examples/edn2cbor \
                 examples/compare_edn_to_cbor.sh

${includes} &: $(local-sources)
	$(MAKE) -C examples

.PHONY: validate
validate:
	@echo running $(MAKE) in examples/ directory
	(cd examples && $(MAKE) validate)
