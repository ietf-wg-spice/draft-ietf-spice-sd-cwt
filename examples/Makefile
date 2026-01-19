noext = issuer_cwt kbt nested_issuer_cwt nested_cwt nested_kbt decoy
cbor = $(noext:=.cbor)
compare-edn = $(cbor:cbor=edn)
other-edn = first-disclosure first-redacted chosen_disclosures elided-kbt
direct-edn = $(compare-edn) $(other-edn:=.edn) chosen_nested_disclosures.edn
other-direct = first-disclosure.cborseq first-blinded-hash.txt
pygenerated = $(direct-edn) $(cbor) $(other-direct)
keys = ../holder_privkey.pem ../issuer_privkey.pem
#cddl = #split into sections
full-cddl = ../sd-cwts.cddl

SED = gsed
CDDL_RUBY = cddl #/opt/homebrew/opt/ruby/lib/ruby/gems/bin/cddl
CDDL_RS = "${HOME}/.cargo/bin/cddl"

all: build validate-cbor validate-edn

# This construction only runs sd-cwt.py once, but requires make version 4.x
${pygenerated} &: sd-cwt.py salt_list.csv decoy_list.csv $(keys)
	python3 sd-cwt.py

first-disclosure.pretty: first-disclosure.cborseq
	cbor2pretty.rb $< > $@
	# This sed command replaces the comment after the salt with a comment just say "16-byte salt"
	# Note: using pipe character as a sed delimiter below
	${SED} -i -r -e 's|^( +[A-Fa-f0-9]{32} *#).*$$|\1 16-byte salt|' $@

#encrypted.edn: enc_disc.py
#	python3 enc_disc.py
#	touch encrypted.edn

.PHONY: build

build: $(pygenerated) first-disclosure.pretty #encrypted.edn

.PHONY: validate-cddl
validate-cbor: $(full-cddl) $(cbor)
	${CDDL_RS} compile-cddl --cddl ${full-cddl}
	for c in $(cbor); do ${CDDL_RUBY} ${full-cddl} validate $${c}; done

validate-progs = compare_edn_to_cbor.sh edn2cbor
.PHONY: validate-edn
validate-edn: $(compare-edn) $(cbor) $(validate-progs)
	for e in ${compare-edn}; do ./compare_edn_to_cbor.sh $${e}; done
	echo "Manually verify elided-kbt.edn"

.PHONY: clean
clean:
	rm *.cbor *.cbor.tmp *.edn *.cborseq *.pretty first-blinded-hash.txt


# Building the SD-CWT draft has the following logical dependencies:
# 
#   Section 3.1: unredacted-payload.edn -> edn2cbor; 
#        py: unredact (strip tags) from to_be_redacted_payload
#        py: generate unredacted-payload.cbor 
#        byte compare the two files
#
#   Section 3.2: py:generate disclosures.edn, redacted_payload.edn
#        py: generate issuer-cwt.edn
#        edn2cbor and compare with issuer-cwt.cbor
#
#        py: first-disclosure.edn
#
#        cbor2pretty: first-disclosure.cbor first-disclosure.pretty
#
#        py: first-blinded-hash.txt
#
#        py: first-redacted.edn
#
#   Section 4:
#        py: chosen-disclosures.edn
#
#        py: elided-kwt.edn
#
#   Section 6.1:
#        2 small snippets of CDDL (manually updated)
#
#   Section 7.2:
#        large snippet of CDDL for SD-CWT (manually updated)
#
#   Section 8.1:
#        large snippet of CDDL for KBT (manually updated)
#
#   Section 10: decoy digest
#        py: generate issued disclosures from nested example
#        py: generate redactions from nested exampled
#
#
#   Section 12.1: full basic example
#	py: generate CBOR basic example
#       edn2cbor annotated EDN used in draft and compare
#
#   Section 12.2: nested example
#       py: generate CBOR nested example
#       edn2cbor annotated EDN used in draft and compare
#
#   Appendix A: full CDDL
#       validate CDDL against all four full CBOR instance docs
#
#   Appendix C: keys
#       (later) convert pem keys to all the other formats shown


