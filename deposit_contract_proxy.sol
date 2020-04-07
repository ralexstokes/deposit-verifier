pragma solidity ^0.6.4;

interface DepositContract {
    function deposit(bytes, bytes32, bytes, bytes32) external payable;
}

library DepositSSZ {
    uint constant WEI_PER_GWEI = 1e9;
    // Constant related to versioning serializations of deposits on eth2
    bytes32 constant DEPOSIT_DOMAIN = 0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9;

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
    function computeSigningRoot(
        bytes memory publicKey,
        bytes32 withdrawalCredentials,
        uint amount
    ) internal pure returns (bytes32) {
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
}

library BLSSignature {
    // NOTE: precompile addresses are placeholders
    uint8 constant BLS12_381_PAIRING_PRECOMPILE_ADDRESS = 0xA;
    uint8 constant BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS = 0xB;
    uint8 constant BLS12_381_G2_ADD_ADDRESS = 0xC;
    uint8 constant BLS12_381_G2_MULTIPLY_ADDRESS = 0xD;
    string constant BLS_SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    // bytes constant BLS12_381_FIELD_MODULUS = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint8 constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;

    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint a;
        uint b;
    };

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

    function expandMessage(bytes32 message) private pure returns (bytes memory) {
        // uint LEN_IN_BYTES = 256;
        // TODO implement `expand_message_xmd` with `message`, `DST` and `LEN_IN_BYTES`
        return abi.encodePacked(
            sha256(message),
            sha256(message),
            sha256(message),
            sha256(message),
            sha256(message),
            sha256(message),
            sha256(message),
            sha256(message),
        );
    }

    function sliceToUint(bytes memory data, uint start, uint end) private pure returns (uint) {
        uint length = end - start;
        assert(length >= 0);
        assert(length <= 32);

        uint result
        for (uint i = 0; i < length; i++) {
            byte b = data[start+i];
            result = result + (uint8(b) * 2**(8*(length-i-1)));
        }
        return result;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    function reduceModulo(bytes memory data, uint start, uint end) private view returns (bytes memory result) {
        uint length = end - start;
        assert (length >= 0);

        bool success;
        assembly {
            let p := mload(0x40)

            mstore(p,                   length)                        // length of base
            mstore(add(p, 0x20),        0x20)                          // length of exponent
            mstore(add(p, 0x40),        48)                            // length of modulus
            // NOTE: we copy the base from `data`
            for
                { let i := 0 }
                lt(i, length)
                {  i := add(i, 1) }
            {
                mstore8(                                               // base
                    add(p, add(0x60, i)),
                    byte(add(start, i), data)
                )
            }
            mstore(add(p, add(0x60, length)), 1)                       // exponent
            mstore(add(p, add(0x80, length)), 0x1a0111ea397fe69a4b1ba7b6434bacd7) // modulus, pt. 1
            mstore(add(p, add(0xA0, length)), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab) // modulus, pt 2

            success := staticcall(
                sub(gas(), 2000),
                MOD_EXP_PRECOMPILE_ADDRESS,
                p,
                add(0xC0, length),
                result,
                48)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to modular exponentiation precompile failed");
    }

    function convertSliceToFp(bytes memory data, uint start, uint end) private view returns (Fp) {
        bytes memory fieldElement = reduceModulo(data, start, end);
        uint a = sliceToUint(fieldElement, 32, 48);
        uint b = sliceToUint(fieldElement, 0, 32);
        return Fp(a, b);
    }

    function hashToField(bytes32 message) private view returns (Fp2[2] memory result) {
        bytes memory some_bytes = expandMessage(message);
        result[0] = Fp2(
            convertSliceToFp(some_bytes, 0, 64),
            convertSliceToFp(some_bytes, 64, 128)
        );
        result[1] = Fp2(
            convertSliceToFp(some_bytes, 128, 192),
            convertSliceToFp(some_bytes, 192, 256)
        );
        return;
    }

    function mapToCurve(Fp2 memory input) private view returns (G2Point result) {
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS,
                input,
                128,
                result,
                256,
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to map to curve precompile failed");
    }

    function addG2(G2Point a, G2Point b) private view returns (G2Point result) {
        uint[16] memory input;
        input[0]  = a.X.a.a;
        input[1]  = a.X.a.b;
        input[2]  = a.X.b.a;
        input[3]  = a.X.b.b;
        input[4]  = a.Y.a.a;
        input[5]  = a.Y.a.a;
        input[6]  = a.Y.a.b;
        input[7]  = a.Y.b.a;

        input[8]  = b.X.a.a;
        input[9]  = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;
        input[12] = b.Y.a.a;
        input[13] = b.Y.a.a;
        input[14] = b.Y.a.b;
        input[15] = b.Y.b.a;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_G2_ADD_ADDRESS,
                input,
                512,
                result,
                256,
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to addition in G2 precompile failed");
    }

    // Implements v6 of "hash to the curve" of the IETF BLS draft.
    function hashToCurve(bytes32 message) private view returns (G2Point) {
        Fp2[2] memory messageElementsInField = hashToField(message);
        G2Point firstPoint = mapToCurve(messageElementsInField[0]);
        G2Point secondPoint = mapToCurve(messageElementsInField[1]);
        return addG2(firstPoint, secondPoint);
    }

    function paring(G1Point u, G2Point v) private view returns (bytes32 result) {
        uint[12] memory input;

        input[0] =  u.X.a;
        input[1] =  u.X.b;
        input[2] =  u.Y.a;
        input[3] =  u.Y.b;

        input[4] =  v.X.a.a;
        input[5] =  v.X.a.b;
        input[6] =  v.X.b.a;
        input[7] =  v.X.b.b;
        input[8] =  v.Y.a.a;
        input[9] =  v.Y.a.b;
        input[10] = v.Y.b.a;
        input[11] = v.Y.b.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_PAIRING_PRECOMPILE_ADDRESS,
                input,
                384,
                result,
                32,
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to pairing precompile failed");
    }

    // Return the generator of G1.
    function P1() private pure returns (G1Point) {
        return G1Point(
            Fp(
                31827880280837800241567138048534752271,
                88385725958748408079899006800036250932223001591707578097800747617502997169851,
            ),
            Fp(
                11568204302792691131076548377920244452,
                114417265404584670498511149331300188430316142484413708742216858159411894806497
            ),
        );
    }

    function decodeG1Point(bytes memory encodedX, Fp Y) private pure returns (G1Point) {
        uint a = sliceToUint(encodedX, 32, 48);
        uint b = sliceToUint(encodedX, 0, 32);
        Fp X = Fp(a, b);
        return G1Point(X,Y);
    }

    function decodeG2Point(bytes memory encodedX, Fp2 Y) private pure returns (G2Point) {
        uint aa = sliceToUint(encodedX, 32, 48);
        uint ab = sliceToUint(encodedX, 0, 32);
        uint ba = sliceToUint(encodedX, 80, 96);
        uint bb = sliceToUint(encodedX, 48, 80);
        Fp2 X = Fp2(
            Fp(aa,ab),
            Fp(ba, bb),
        );
        return G2Point(X, Y);
    }

    function isValid(
        bytes32 message,
        bytes memory encodedPublicKey,
        bytes memory encodedSignature,
        Fp publicKeyYCoordinate,
        Fp2 signatureYCoordinate,
    ) internal view returns (bool) {
        G1Point publicKey = decodeG1Point(encodedPublicKey, publicKeyYCoordinate);
        G2Point signature = decodeG2Point(encodedSignature, signatureYCoordinate);

        G2Point messageOnCurve = hashToCurve(message);
        return pairing(publicKey, messageOnCurve) == pairing(P1(), signature);
    }
}

contract DepositContractProxy  {
    uint constant PUBLIC_KEY_LENGTH = 48;
    uint constant SIGNATURE_LENGTH = 96;

    DepositContract depositContract;

    constructor(address depositContractAddress) public {
        depositContract = DepositContract(depositContractAddress);
    }

    function verifyAndDeposit(
        bytes memory publicKey,
        bytes32 withdrawalCredentials,
        bytes memory signature,
        bytes32 depositDataRoot,
        Fp publicKeyYCoordinate,
        Fp2 signatureYCoordinate,
    ) public payable {
        require(publicKey.length == PUBLIC_KEY_LENGTH, "incorrectly sized public key");
        require(signature.length == SIGNATURE_LENGTH, "incorrectly sized signature");

        bytes32 signingRoot = DepositSSZ.computeSigningRoot(
            publicKey,
            withdrawalCredentials,
            msg.value
        );

        require(
            BLSSignature.isValid(
                signingRoot,
                publicKey,
                signature,
                publicKeyYCoordinate,
                signatureYCoordinate
            ),
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
