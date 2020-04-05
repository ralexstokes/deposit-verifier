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
    address constant BLS12_381_PAIRING_PRECOMPILE_ADDRESS = 0xA;
    address constant BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS = 0xB;

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

    // Returns an element in Fp2
    function hashToField(bytes32 message) private pure returns (Fp2 result) {
        // TODO implement v6 hash to field
        result.a.a = sha256(message);
        result.a.b = sha256(message);
        result.b.a = sha256(message);
        result.b.b = sha256(message);
        return;
    }

    function mapToCurve(Fp2 fieldElement) private view returns (G2Point point) {
        bool success;
        assembly {
            success := staticcall(
                sub(gas, 2000),
                BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS,
                fieldElement,
                128,
                point,
                256,
            )
        }
        require(success, "call to map to curve precompile failed");
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
                sub(gas, 2000),
                BLS12_381_PAIRING_PRECOMPILE_ADDRESS,
                input,
                384,
                result,
                32,
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid }
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
        Fp X = Fp(
            uint(encodedX[32:48]),
            uint(encodedX[0:32]),
        );
        return G1Point(X,Y);
    }

    function decodeG2Point(bytes memory encodedX, Fp2 Y) private pure returns (G2Point) {
        Fp2 X = Fp2(
            Fp(
                uint(encodedX[32:48]),
                uint(encodedX[0:32]),
            ),
            Fp(
                uint(encodedX[80:96]),
                uint(encodedX[48:80]),
            )
        );
        return G2Point(X, Y);
    }

    function isValid(
        bytes32 message,
        bytes memory encodedPublicKey,
        bytes memory encodedSignature,
        Fp publicKeyYCoordinate,
        Fp2 signatureYCoordinate,
    ) internal returns (bool) {
        G1Point publicKey = decodeG1Point(encodedPublicKey, publicKeyYCoordinate);
        G2Point signature = decodeG2Point(encodedSignature, signatureYCoordinate);

        Fp2 messageInField = hashToField(message);
        G2Point messageOnCurve = mapToCurve(messageInField);
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
