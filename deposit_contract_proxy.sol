pragma solidity ^0.6.4;

interface DepositContract {
    function deposit(bytes, bytes32, bytes, bytes32) external payable;
}


contract DepositContractProxy  {
    uint constant WEI_PER_GWEI = 1e9;
    uint constant PUBLIC_KEY_LENGTH = 48;
    uint constant SIGNATURE_LENGTH = 96;
    // Constant related to versioning serializations of deposits on eth2
    bytes32 constant DEPOSIT_DOMAIN = 0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9;

    DepositContract depositContract;

    constructor(address _depositContractAddress) public {
        depositContract = DepositContract(_depositContractAddress);
    }

    // Return a `wei` value in units of Gwei and serialize as a (LE) `bytes8`.
    function serializeAmount(uint amount) pure returns (bytes memory) {
        uint depositAmount = amount / WEI_PER_GWEI;

        bytes memory encodedAmount = new bytes(8);

        for (uint i = 0; i < 8; i++) {
            encodedAmount[i] = byte(uint8(depositAmount / (2**(8*i))));
        }

        return encodedAmount;
    }

    // TODO fix comments
    // Compute the "signing root" from the deposit message. This root is the Merkle root of a specific tree
    // specified by SSZ serialization that takes as leaves chunks of 32 bytes.
    //             |--------------- 32 bytes ---------------|
    // input data: |-------- publicKey: byte[48] --------|
    // padded data to yield leaves
    // and then recursively hash pairs of leaves until there is only one value.
    // NOTE: This computation is done manually in ``computeSigningRoot``.
    function computeSigningRoot(
        bytes memory publicKey,
        bytes32 withdrawalCredentials,
        uint amount
    ) pure returns (bytes32) {
        bytes memory serializedAmount = serializeAmount(amount);

        bytes memory serializedPublicKey = new bytes(64);
        for (uint i = 0; i < PUBLIC_KEY_LENGTH; i++) {
            serializedPublicKey[i] = publicKey[i];
        }

        bytes32 publicKeyRoot = sha256(serializedPublicKey);
        bytes32 firstNode = sha256(abi.encodePacked(publicKeyRoot, withdrawalCredentials));

        bytes memory restOfChunks = new bytes(64);
        for (uint i = 0; i < 8; i++) {
            restOfChunks[i] = serializedAmount[i];
        }

        bytes32 secondNode = sha256(restOfChunks);

        bytes32 depositMessageRoot = sha256(abi.encodePacked(firstNode, secondNode));

        return sha256(abi.encodePacked(depositMessageRoot, DEPOSIT_DOMAIN));
    }

    function mapToField(bytes32 message) pure returns (bytes memory) {
        // TODO what is the latest map to field?
    }

    function mapToCurve(bytes memory fieldElement) pure returns (bytes memory) {
        // TODO call precompile for map to curve
    }

    function paring(bytes memory a, bytes memory b) pure returns (bytes memory) {
        // TODO call precompile for pairing operation
        // TODO is there a shortcut for a pairing equality check?
    }

    function validBLSSignature(
        bytes32 message,
        bytes memory publicKey,
        bytes memory signature
    ) pure returns (bool) {
        bytes memory messageInField = mapToField(message);
        bytes memory messageOnCurve = mapToCurve(messageInField);
        // TODO define generator
        generator = new bytes(48);
        // TODO verify ordering of the calls
        return pairing(signature, generator) == pairing(messageOnCurve, publicKey);
    }

    function verifyAndDeposit(
        bytes memory publicKey,
        bytes32 withdrawalCredentials,
        bytes memory signature,
        bytes32 depositDataRoot
    ) public payable {
        require(publicKey.length == PUBLIC_KEY_LENGTH, "incorrectly sized public key");
        require(signature.length == SIGNATURE_LENGTH, "incorrectly sized signature");

        bytes32 signingRoot = computeSigningRoot(publicKey, withdrawalCredentials, msg.value);

        require(
            validBLSSignature(signingRoot, publicKey, signature),
            "invalid BLS signature given deposit data"
        );

        depositContract.deposit{value: msg.value}(
            publicKey,
            withdrawalCredentials,
            signature,
            depositDataRoot
        );
    }
}
