# deposit-contract-verifying-proxy

A smart contract to enhance the user experience of the `eth2` deposit contract.

# NOTICE

This smart contract has not been tested, audited or formally verified. It should
be considered pre-alpha. USE AT YOUR OWN RISK.

## What is this?

Validators of the eth2 network join by making a deposit to a smart contract called the __deposit contract__. This contract makes a cryptographic committment to the validator which can then be consumed on the eth2 network. Importantly, a given deposit has an associated amount of ETH attached meant to move to the validator on the eth2 network. This deposit is "one-way" for the time being in that any ETH sent to the deposit contract is not recoverable. Given that ETH sent to the deposit contract is not recoverable, any deposit accepted by the deposit contract but that is later found to be invalid by the eth2 network results in a permanent loss of ETH. Refer to the [eth2-specs](https://github.com/ethereum/eth2.0-specs) for more information.

One part of making a valid deposit is the inclusion of a valid signature according to the eth2 signature scheme `BLS`. In an attempt to keep the deposit contract minimal (and therefore easier to get correct), the verification of the `BLS` signature is omitted. Moreover, the efficient verification of this signature requires precompiles that are scheduled for the eth1 `Berlin` hardfork but are not currently available on mainnet and were not when the deposit contract was written. 

This "verifying proxy" contract wraps the deposit contract, requiring a valid `BLS` signature before proceeding to make a call to the `deposit` function on the deposit contract. This proxy contract enhances the usability of the deposit contract by reducing the chance a potential validator will make a bad deposit resulting in lost ETH.

# How to compile the contract

With a sufficient version of the Solidity compiler (refer to the contract's `pragma solidity`), you can run:

```shell
$ make compile
```

to generate the `ABI` definition and the hex-encoded EVM bytecode.

These artifacts (along with the corresponding assets for the deposit contract) are included in this repo for convenience.

# How to run the tests

## Installation 

The project uses a Python stack for unit tests. It is suggested to use `pipenv` (https://pipenv.pypa.io/en/latest/) to manage dependencies.

Once `pipenv` is installed:

``` shell
$ pipenv --python $PATH_TO_PY_38 shell
# once inside the virtualenv
$ pipenv install
```

## Testing

Once all of the dependencies are installed, you can use `pytest` (inside the virtualenv you have created).

``` shell
$ pytest tests
```
