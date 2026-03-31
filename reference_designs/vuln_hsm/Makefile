# Vulnerable HSM — Makefile
# Expected: zeroization properties FAIL (this is intentional)

SBY ?= sby

.PHONY: verify clean

verify:
	-$(SBY) -f vuln_hsm.sby

clean:
	rm -rf vuln_hsm_prove/
