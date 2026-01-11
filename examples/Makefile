cbor = issuer_cwt.cbor kbt.cbor nested_issuer_cwt.cbor nested_cwt.cbor nested_kbt.cbor decoy.cbor
edn  = issuer_cwt.edn kbt.edn nested_issuer_cwt.edn nested_cwt.edn nested_kbt.cbor decoy.cbor
manual-edn = first-disclosure.edn first-redacted.edn chosen-disclosures.edn
manual-cbor = first-disclosure.cborseq
primary = $(edn)  first-blinded-hash.txt
keys = ../holder_privkey.pem ../issuer_privkey.pem
generated = $(cbor) $(edn) first-blinded-hash.txt
CDDL_RUBY = /opt/homebrew/opt/ruby/lib/ruby/gems/bin/cddl
CDDL_RS = "${HOME}/.cargo/bin/cddl"

help:
	echo 'To rebuild the examples, run:'
	echo '    python3 sd-cwt.py && make first-disclosure.pretty'

all: $(primary)

$(primary): sd-cwt.py first-disclosure.pretty $(keys)
	python3 sd-cwt.py

# Section 3.2
first-disclosure.pretty: first-disclosure.cborseq
	cbor2pretty.rb $< > $@
	# This sed command replaces the comment after the salt with a comment just say "16-byte salt"
	# Note: using pipe character as a sed delimiter below
	gsed -i -r -e 's|^( +[A-Fa-f0-9]{32} *#).*$$|\1 16-byte salt|' $@

validate: validate-cddl validate-edn

validate-cddl: ../sd-cwts.cddl $(cbor)
	$CDDL_RS compile-cddl --cddl ../sd-cwts.cddl
	for c in $(cbor); do $CDDL_RUBY ../sd-cwts.cddl validate $${c}; done

validate-edn: validate issuer_cwt.edn kbt.edn nested.edn
	compare_edn_to_cbor.sh issuer_cwt.edn
	compare_edn_to_cbor.sh kbt.edn
	compare_edn_to_cbor.sh nested_issuer_cwt.edn
	compare_edn_to_cbor.sh nested_cwt.edn
	compare_edn_to_cbor.sh nested_kbt.edn
	compare_edn_to_cbor.sh decoy.edn
	echo "Manually verify elided-kbt.edn"


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


