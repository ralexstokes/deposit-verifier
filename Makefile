compile:
	solc --overwrite --abi -o contracts contracts/deposit_contract_proxy.sol
	solc --overwrite --bin -o contracts contracts/deposit_contract_proxy.sol

clean:
	rm contracts/*bin
	rm contracts/*abi
