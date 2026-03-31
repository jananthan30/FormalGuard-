# Vulnerable AES — Makefile
# Expected: timing properties FAIL (this is intentional)

SBY ?= sby

.PHONY: verify clean

verify:
	-$(SBY) -f vuln_aes.sby

clean:
	rm -rf vuln_aes_prove/
