MAKEFLAGS += --no-builtin-rules

cbor-noext = issuer_cwt kbt nested_issuer_cwt nested_cwt nested_kbt decoy
cbor = $(cbor-noext:=.cbor)
compare-edn = $(cbor:cbor=edn)
other-edn = first-disclosure first-redacted chosen-disclosures elided-kbt
direct-edn = $(compare-edn) $(other-edn:=.edn) chosen-nested-disclosures.edn
other-direct = first-disclosure.cborseq first-blinded-hash.txt
pygenerated = $(direct-edn) $(cbor) $(other-direct)
keys = ../holder_privkey.pem ../issuer_privkey.pem
cddl = ../header.cddl ../main-sd-cwt.cddl ../kbt.cddl ../preissued.cddl \
       ../legal-values.cddl ../salted-array.cddl ../aead.cddl \
       ../redacted-simple-tag.cddl
full-cddl = ../sd-cwts.cddl

# Check make version (must be 4.0 or higher)
ifeq ($(filter 4.%,$(MAKE_VERSION)),)
    $(error This Makefile requires GNU Make 4.0 or higher. Current version: $(MAKE_VERSION))
endif

#CDDL_RUBY := cddl
# Check for Ruby cddl program in PATH
#ifeq ($(shell command -v cddl 2>/dev/null),)
#    $(error Required program 'cddl' not found in PATH)
#endif

# Check for Ruby cbor2pretty.rb program in PATH
#ifeq ($(shell command -v cbor2pretty.rb 2>/dev/null),)
#    $(error Required program 'cbor2pretty.rb' not found in PATH)
#endif

#CDDL_RS := "${HOME}/.cargo/bin/cddl"
# Check for Rust cddl program in ~/.cargo/bin
#ifeq ($(shell command -v "${HOME}/.cargo/bin/cddl" 2>/dev/null),)
#    undefine CDDL_RS
#else
#    CDDL_RS := "${HOME}/.cargo/bin/cddl"
#endif

# Check for GNU sed and set SED variable
ifeq ($(shell sed --version >/dev/null 2>&1 && echo yes),yes)
    SED := sed
else ifeq ($(shell command -v gsed 2>/dev/null),)
    $(error GNU sed must be installed. Install 'sed' (GNU version) or 'gsed')
else
    SED := gsed
endif

#SED := gsed
#ifneq ($(shell ${SED} --version >/dev/null 2>&1 && echo yes),yes)
#    $(error GNU sed must be installed. Install 'sed' (GNU version) or 'gsed')
#endif

#PYTHON := python3

#.PHONY: vars
#vars:
#	@echo "Printing system variables..."
#	@echo "Make version: $(MAKE_VERSION)"
#	@echo "Sed: ${SED}"
#	@echo "Rust CDDL tool ${CDDL_RS}"

ifeq (true,$(CI))
    PYTHON := python3
else
#   If not set, manually set BUNDLE_PATH to the full path of ../lib/.gems
    PYTHON := ../lib/.venv/bin/python3
endif
CDDL_RS := ${BUNDLE_PATH}/../.cargo/bin/cddl
CDDL_RUBY := ${BUNDLE_PATH}/bin/cddl
CBOR2PRETTY := ${BUNDLE_PATH}/bin/cbor2pretty.rb


.PHONY: all
all: build

# This construction only runs sd-cwt.py once, but requires make version 4.x
${pygenerated} &: sd-cwt.py salt_list.csv decoy_list.csv $(keys)
	${PYTHON} sd-cwt.py

first-disclosure.pretty: first-disclosure.cborseq
	${CBOR2PRETTY} $< > $@
	# This sed command replaces the comment after the salt with a comment just say "16-byte salt"
	# Note: using pipe character as a sed delimiter below
	${SED} -i -r -e 's|^( +[A-Fa-f0-9]{32} *#).*$$|\1 16-byte salt|' $@

aead-key.txt aead-claim-array.edn &: enc-disc.py
	${PYTHON} enc-disc.py

.PHONY: build
build: $(pygenerated) first-disclosure.pretty aead-key.txt aead-claim-array.edn

.PHONY: validate
validate: validate-cbor validate-edn

${full-cddl}: $(cddl)
	cat $^ > ${full-cddl}

.PHONY: validate-cddl
validate-cbor: $(full-cddl) $(cbor)
ifdef CDDL_RS
	# only run the Rust CDDL verification tool if it is installed
	${CDDL_RS} compile-cddl --cddl ${full-cddl}
endif
	for c in $(cbor); do ${CDDL_RUBY} ${full-cddl} validate $${c}; done

validate-progs = compare_edn_to_cbor.sh edn2cbor
.PHONY: validate-edn
validate-edn: $(compare-edn) $(cbor) $(validate-progs)
	for e in ${compare-edn}; do ./compare_edn_to_cbor.sh $${e}; done
	echo "Manually verify elided-kbt.edn"

.PHONY: clean
clean:
	-rm -f *.cbor *.cbor.tmp *.edn *.cborseq *.pretty first-blinded-hash.txt


# Beware the following manual build steps if something major changes:
#
#   Section 3.1:
#        the example claimset is manual. If it diverges from the claimset
#        used in examples/sd-cwt.py, the generated examples will be wrong
#
#   Section 14.2: nested disclosures examples (all three)
#        the example claimset is manual. If it diverges from the claimset
#        used in examples/sd-cwt.py, the generated examples will be wrong
#
#        The sample claims (the second example in the section)
#        is manually pasted in from the sd_claims COSE Header parameter
#        from the examples/issued_cwt.edn
#
#        the example resulting claimset is also manual.
#
#
#   Appendix C: keys
#       manually convert pem keys to all the other formats shown
