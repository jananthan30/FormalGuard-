# AES-256 Reference Core — Makefile

SBY ?= sby

.PHONY: verify clean

verify:
	$(SBY) -f aes256_core.sby

clean:
	rm -rf aes256_core_prove/ aes256_core_bmc/
