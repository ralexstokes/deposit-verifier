// SPDX-License-Identifier: The Unlicense
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;

interface DepositContract {
    function deposit(
        bytes calldata publicKey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external payable;
}

contract DepositContractProxy  {
    uint constant PUBLIC_KEY_LENGTH = 48;
    uint constant SIGNATURE_LENGTH = 96;

    uint constant WEI_PER_GWEI = 1e9;
    // Constant related to versioning serializations of deposits on eth2
    bytes32 constant DEPOSIT_DOMAIN = 0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9;

    uint8 constant BLS12_381_PAIRING_PRECOMPILE_ADDRESS = 0x10;
    uint8 constant BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS = 0x12;
    uint8 constant BLS12_381_G2_ADD_ADDRESS = 0xD;
    string constant BLS_SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_+";
    bytes1 constant BLS_BYTE_WITHOUT_FLAGS_MASK = bytes1(0x1f);

    uint8 constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;

    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint a;
        uint b;
    }

    // Fp2 is an extension field element with the coefficient of the
    // quadratic non-residue stored in `b`, i.e. p = a + i * b
    struct Fp2 {
        Fp a;
        Fp b;
    }

    // G1Point represents a point on BLS12-381 over Fp with coordinates (X,Y);
    struct G1Point {
        Fp X;
        Fp Y;
    }

    // G2Point represents a point on BLS12-381 over Fp2 with coordinates (X,Y);
    struct G2Point {
        Fp2 X;
        Fp2 Y;
    }

    DepositContract depositContract;

    constructor(address depositContractAddress) public {
        depositContract = DepositContract(depositContractAddress);
    }

    // Return a `wei` value in units of Gwei and serialize as a (LE) `bytes8`.
    function serializeAmount(uint amount) private pure returns (bytes memory) {
        uint depositAmount = amount / WEI_PER_GWEI;

        bytes memory encodedAmount = new bytes(8);

        for (uint i = 0; i < 8; i++) {
            encodedAmount[i] = byte(uint8(depositAmount / (2**(8*i))));
        }

        return encodedAmount;
    }

    // Compute the "signing root" from the deposit message. This root is the Merkle root
    // of a specific tree specified by SSZ serialization that takes as leaves chunks of 32 bytes.
    // NOTE: This computation is done manually in ``computeSigningRoot``.
    // NOTE: function is exposed for testing...
    function computeSigningRoot(
        bytes memory publicKey,
        bytes32 withdrawalCredentials,
        uint amount
    ) public pure returns (bytes32) {
        bytes memory serializedPublicKey = new bytes(64);
        for (uint i = 0; i < PUBLIC_KEY_LENGTH; i++) {
            serializedPublicKey[i] = publicKey[i];
        }

        bytes32 publicKeyRoot = sha256(serializedPublicKey);
        bytes32 firstNode = sha256(abi.encodePacked(publicKeyRoot, withdrawalCredentials));

        bytes memory amountRoot = new bytes(64);
        bytes memory serializedAmount = serializeAmount(amount);
        for (uint i = 0; i < 8; i++) {
            amountRoot[i] = serializedAmount[i];
        }
        bytes32 secondNode = sha256(amountRoot);

        bytes32 depositMessageRoot = sha256(abi.encodePacked(firstNode, secondNode));
        return sha256(abi.encodePacked(depositMessageRoot, DEPOSIT_DOMAIN));
    }


    // NOTE: function exposed for testing...
    function expandMessage(bytes32 message) public pure returns (bytes memory) {
        bytes memory b0Input = new bytes(143);
        for (uint i = 0; i < 32; i++) {
            b0Input[i+64] = message[i];
        }
        b0Input[96] = 0x01;
        for (uint i = 0; i < 44; i++) {
            b0Input[i+99] = bytes(BLS_SIG_DST)[i];
        }

        bytes32 b0 = sha256(abi.encodePacked(b0Input));

        bytes memory output = new bytes(256);
        bytes32 chunk = sha256(abi.encodePacked(b0, byte(0x01), bytes(BLS_SIG_DST)));
        assembly {
            mstore(add(output, 0x20), chunk)
        }
        for (uint i = 2; i < 9; i++) {
            bytes32 input;
            assembly {
                input := xor(b0, mload(add(output, add(0x20, mul(0x20, sub(i, 2))))))
            }
            chunk = sha256(abi.encodePacked(input, byte(uint8(i)), bytes(BLS_SIG_DST)));
            assembly {
                mstore(add(output, add(0x20, mul(0x20, sub(i, 1)))), chunk)
            }
        }

        return output;
    }

    function sliceToUint(bytes memory data, uint start, uint end) private pure returns (uint) {
        uint length = end - start;
        assert(length >= 0);
        assert(length <= 32);

        uint result;
        for (uint i = 0; i < length; i++) {
            byte b = data[start+i];
            result = result + (uint8(b) * 2**(8*(length-i-1)));
        }
        return result;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    // Copying of the base is cribbed from the following:
    // https://github.com/ethereum/solidity-examples/blob/f44fe3b3b4cca94afe9c2a2d5b7840ff0fafb72e/src/unsafe/Memory.sol#L57-L74
    function reduceModulo(bytes memory data, uint start, uint end) private view returns (bytes memory) {
        uint length = end - start;
        assert (length >= 0);
        assert (length <= data.length);

        bytes memory result = new bytes(48);

        bool success;
        assembly {
            let p := mload(0x40)
            // length of base
            mstore(p, length)
            // length of exponent
            mstore(add(p, 0x20), 0x20)
            // length of modulus
            mstore(add(p, 0x40), 48)
            // base
            // first, copy slice by chunks of EVM words
            let ctr := length
            let src := add(add(data, 0x20), start)
            let dst := add(p, 0x60)
            for { }
                or(gt(ctr, 0x20), eq(ctr, 0x20))
                { ctr := sub(ctr, 0x20) }
            {
                mstore(dst, mload(src))
                dst := add(dst, 0x20)
                src := add(src, 0x20)
            }
            // next, copy remaining bytes in last partial word
            let mask := sub(exp(256, sub(0x20, ctr)), 1)
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dst), mask)
            mstore(dst, or(destpart, srcpart))
            // exponent
            mstore(add(p, add(0x60, length)), 1)
            // modulus
            let modulusAddr := add(p, add(0x60, add(0x10, length)))
            mstore(modulusAddr, or(mload(modulusAddr), 0x1a0111ea397fe69a4b1ba7b6434bacd7)) // pt 1
            mstore(add(p, add(0x90, length)), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab) // pt 2
            success := staticcall(
                sub(gas(), 2000),
                MOD_EXP_PRECOMPILE_ADDRESS,
                p,
                add(0xB0, length),
                add(result, 0x20),
                48)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to modular exponentiation precompile failed");
        return result;
    }

    function convertSliceToFp(bytes memory data, uint start, uint end) private view returns (Fp memory) {
        bytes memory fieldElement = reduceModulo(data, start, end);
        uint a = sliceToUint(fieldElement, 0, 16);
        uint b = sliceToUint(fieldElement, 16, 48);
        return Fp(a, b);
    }

    // NOTE: function is exposed for testing...
    function hashToField(bytes32 message) public view returns (Fp2[2] memory result) {
        bytes memory some_bytes = expandMessage(message);
        result[0] = Fp2(
            convertSliceToFp(some_bytes, 0, 64),
            convertSliceToFp(some_bytes, 64, 128)
        );
        result[1] = Fp2(
            convertSliceToFp(some_bytes, 128, 192),
            convertSliceToFp(some_bytes, 192, 256)
        );
    }

    function mapToCurve(Fp2 memory fieldElement) public view returns (G2Point memory result) {
        uint[4] memory input;
        input[0] = fieldElement.a.a;
        input[1] = fieldElement.a.b;
        input[2] = fieldElement.b.a;
        input[3] = fieldElement.b.b;

        uint[8] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS,
                input,
                128,
                output,
                256
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to map to curve precompile failed");

        return G2Point(
            Fp2(
                Fp(output[0], output[1]),
                Fp(output[2], output[3])
            ),
            Fp2(
                Fp(output[4], output[5]),
                Fp(output[6], output[7])
            )
        );
    }

    function addG2(G2Point memory a, G2Point memory b) private view returns (G2Point memory) {
        uint[16] memory input;
        input[0]  = a.X.a.a;
        input[1]  = a.X.a.b;
        input[2]  = a.X.b.a;
        input[3]  = a.X.b.b;
        input[4]  = a.Y.a.a;
        input[5]  = a.Y.a.b;
        input[6]  = a.Y.b.a;
        input[7]  = a.Y.b.b;

        input[8]  = b.X.a.a;
        input[9]  = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;
        input[12] = b.Y.a.a;
        input[13] = b.Y.a.b;
        input[14] = b.Y.b.a;
        input[15] = b.Y.b.b;

        uint[8] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_G2_ADD_ADDRESS,
                input,
                512,
                output,
                256
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to addition in G2 precompile failed");

        return G2Point(
            Fp2(
                Fp(output[0], output[1]),
                Fp(output[2], output[3])
            ),
            Fp2(
                Fp(output[4], output[5]),
                Fp(output[6], output[7])
            )
        );
    }

    // Implements "hash to the curve" from the IETF BLS draft.
    // NOTE: function is exposed for testing...
    function hashToCurve(bytes32 message) public view returns (G2Point memory) {
        Fp2[2] memory messageElementsInField = hashToField(message);
        G2Point memory firstPoint = mapToCurve(messageElementsInField[0]);
        G2Point memory secondPoint = mapToCurve(messageElementsInField[1]);
        return addG2(firstPoint, secondPoint);
    }

    // NOTE: function is exposed for testing...
    function blsPairingCheck(G1Point memory publicKey, G2Point memory messageOnCurve, G2Point memory signature) public view returns (bool) {
        uint[24] memory input;

        input[0] =  publicKey.X.a;
        input[1] =  publicKey.X.b;
        input[2] =  publicKey.Y.a;
        input[3] =  publicKey.Y.b;

        input[4] =  messageOnCurve.X.a.a;
        input[5] =  messageOnCurve.X.a.b;
        input[6] =  messageOnCurve.X.b.a;
        input[7] =  messageOnCurve.X.b.b;
        input[8] =  messageOnCurve.Y.a.a;
        input[9] =  messageOnCurve.Y.a.b;
        input[10] = messageOnCurve.Y.b.a;
        input[11] = messageOnCurve.Y.b.b;

        // NOTE: this constant is -P1, where P1 is the generator of the group G1.
        input[12] = 31827880280837800241567138048534752271;
        input[13] = 88385725958748408079899006800036250932223001591707578097800747617502997169851;
        input[14] = 22997279242622214937712647648895181298;
        input[15] = 46816884707101390882112958134453447585552332943769894357249934112654335001290;

        input[16] =  signature.X.a.a;
        input[17] =  signature.X.a.b;
        input[18] =  signature.X.b.a;
        input[19] =  signature.X.b.b;
        input[20] =  signature.Y.a.a;
        input[21] =  signature.Y.a.b;
        input[22] =  signature.Y.b.a;
        input[23] =  signature.Y.b.b;

        uint[1] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_PAIRING_PRECOMPILE_ADDRESS,
                input,
                768,
                output,
                32
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to pairing precompile failed");

        return output[0] == 1;
    }

    function decodeG1Point(bytes memory encodedX, Fp memory Y) private pure returns (G1Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        uint a = sliceToUint(encodedX, 0, 16);
        uint b = sliceToUint(encodedX, 16, 48);
        Fp memory X = Fp(a, b);
        return G1Point(X,Y);
    }

    function decodeG2Point(bytes memory encodedX, Fp2 memory Y) private pure returns (G2Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        // NOTE: the "flag bits" of the second half of `encodedX` are always == 0x0

        // NOTE: order is important here for decoding point...
        uint aa = sliceToUint(encodedX, 48, 64);
        uint ab = sliceToUint(encodedX, 64, 96);
        uint ba = sliceToUint(encodedX, 0, 16);
        uint bb = sliceToUint(encodedX, 16, 48);
        Fp2 memory X = Fp2(
            Fp(aa, ab),
            Fp(ba, bb)
        );
        return G2Point(X, Y);
    }

    // NOTE: function is exposed for testing...
    function blsSignatureIsValid(
        bytes32 message,
        bytes memory encodedPublicKey,
        bytes memory encodedSignature,
        Fp memory publicKeyYCoordinate,
        Fp2 memory signatureYCoordinate
    ) public view returns (bool) {
        G1Point memory publicKey = decodeG1Point(encodedPublicKey, publicKeyYCoordinate);
        G2Point memory signature = decodeG2Point(encodedSignature, signatureYCoordinate);
        G2Point memory messageOnCurve = hashToCurve(message);

        return blsPairingCheck(publicKey, messageOnCurve, signature);
    }

    function verifyAndDeposit(
        bytes calldata publicKey,
        bytes32 withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot,
        Fp calldata publicKeyYCoordinate,
        Fp2 calldata signatureYCoordinate
    ) public payable {
        require(publicKey.length == PUBLIC_KEY_LENGTH, "incorrectly sized public key");
        require(signature.length == SIGNATURE_LENGTH, "incorrectly sized signature");

        bytes32 signingRoot = computeSigningRoot(
            publicKey,
            withdrawalCredentials,
            msg.value
        );

        require(
            blsSignatureIsValid(
                signingRoot,
                publicKey,
                signature,
                publicKeyYCoordinate,
                signatureYCoordinate
            ),
            "BLS signature verification failed"
        );


        // NOTE: old vyper contract expects a previous (?) version of ABI encoding
        // which we manually encode here. it also seems that we can only put a limited number
        // of arguments into `abi.encodePacked` so we have to break into pieces.
        bytes memory prefix = abi.encodePacked(
            depositContract.deposit.selector,
            uint(0x80),
            uint(0xe0),
            uint(0x120),
            depositDataRoot,
            uint(0x30),
            publicKey,
            uint128(0x0),
            uint(0x20)
        );

        (bool success,) = address(depositContract).call{value: msg.value}(
            abi.encodePacked(
                prefix,
                withdrawalCredentials,
                uint(0x60),
                signature
            )
        );
        require(success, "call to deposit contract failed");
    }
}
