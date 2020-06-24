# NOTE: following the `Makefile` from the `eth2-deposit-contract` submodule for generation of the contract JSON.

JSON_TARGET=deposit_verifier.json

clean:
	@rm -rf build
	@rm -f $JSON_TARGET

# Note: using /bin/echo for macOS support
compile: clean
	@solc --metadata-literal --optimize --optimize-runs 5000000 --bin --abi --combined-json=abi,bin,bin-runtime,srcmap,srcmap-runtime,ast,metadata,storage-layout --overwrite -o build deposit_verifier.sol
	@/bin/echo -n '{"abi": ' > $(JSON_TARGET)
	@cat build/DepositVerifier.abi >> $(JSON_TARGET)
	@/bin/echo -n ', "bytecode": "0x' >> $(JSON_TARGET)
	@cat build/DepositVerifier.bin >> $(JSON_TARGET)
	@/bin/echo -n '"}' >> $(JSON_TARGET)
