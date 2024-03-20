import {ethers} from "hardhat";
import "@nomiclabs/hardhat-etherscan";
import {assert, expect} from "chai";

// const crypto = require('crypto');

const fs = require('fs');

const incorrectInputs = [
    "946114226032418920967126594582827840",
    "252211404666022190610388135805056990740",
    "250203699874957393754930603326313200950",
    "294168951901226811933587358204780889670"
];

const incorrectProof = [
    "6302162678823841200396915311228777342524310647178952242621209430860606417870",
    "5688874101604422809062392686067769974466336383547871872297604857481113209310",
    "13067201362306888280420276685585448577630319898210624528091944232563639673900",
    "15253040417767205464665745126190612115773771949281934081886164082116687122180",
    "1286287796680172736180296629792415589426353119726353867523801064677953938380",
    "10072443203863058952492408939658944706911871289381911835060263441184101246870",
    "13594152181780533529094098669508003919098231319348108349232488431856536079740",
    "19991156839958621917471713965247457880542796239191147501866226782529365125610"
]

function secondHash(array: number[]): string {
    let numbers: number[] = array.slice(2, 4).map(value => BigInt(value));
    let hexString: string = numbers.map(value => value.toString(16)).join('');
    return '0x' + hexString;
}

describe("Verifier", function () {
    let verifier;
    let nearBlockVerification;
    let inputs, proof;
    let tx, gasUsed;
    let compressedProof;

    beforeEach(async () => {
        const verifierFactory = await ethers.getContractFactory("Verifier");
        verifier = await verifierFactory.deploy();
        await verifier.deployed();

        let fileData = fs.readFileSync('test/proof_with_witness.json', 'utf-8');
        let dataParsed = JSON.parse(fileData);
        inputs = dataParsed.inputs;
        proof = dataParsed.proof;

//         console.log("inputs: ", inputs);
//         console.log("proof:", proof);
    });

    it("should successfully execute the verifyProof request", async function () {
        await verifier.verifyProof(proof, inputs);
    });

    it("should successfully execute the verifyCompressedProof request", async function () {
        compressedProof = await verifier.compressProof(proof)
        await verifier.verifyCompressedProof(compressedProof, inputs);
    });

    it("should handle incorrect proof", async function () {
        await expect(verifier.verifyProof(proof, incorrectInputs)).to.be.reverted;

        await expect(verifier.verifyProof(incorrectProof, inputs)).to.be.reverted;
    });

    describe("NearBlockVerification", function () {
        beforeEach(async () => {
            const NearBlockVerification = await ethers.getContractFactory("NearBlockVerification");
            nearBlockVerification = await NearBlockVerification.deploy();
            await nearBlockVerification.deployed();
            await nearBlockVerification.initialize(verifier.address);
        });

        it("should successfully execute the verifyAndSaveProof request", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs, proof);
        });

        it("should handle incorrect proof", async function () {
            await expect(nearBlockVerification.verifyAndSaveProof(incorrectInputs, proof)).to.be.reverted;
            await expect(nearBlockVerification.verifyAndSaveProof(inputs, incorrectProof)).to.be.reverted;
        });

        it("should successfully execute the verifyAndSaveCompressedProof request", async function () {
            compressedProof = await verifier.compressProof(proof);
            await nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof);
        });

        it("should return false for isProofed when input is not proofed", async function () {
            const unProofedInput = ["250203699874957393754930603326313200955", "294168951901226811933587358204780889671"];

            expect(await nearBlockVerification.isProofed(
                unProofedInput
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs.slice(0, 2)
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs.slice(2, 16)
            )).to.equal(false);
        });

        it("should return true for isProofed when input is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs, proof);

            expect(await nearBlockVerification.isProofed(
                inputs.slice(2, 4)
            )).to.equal(true);
        });

        it("should correctly convert array to hash", async function () {
            let proofedInputHashBytes: string = secondHash(inputs);

            expect(await nearBlockVerification.toHash(
                inputs.slice(2, 4),
            )).to.equal(proofedInputHashBytes);
        });

        it("should return false for isProofedHash when inputHash is not proofed", async function () {
            const unProofedInputHash: string = "0xbc23058485c30c426caaf283decba76ddb675ffae9d53bfa1f189889518df031";

            expect(await nearBlockVerification.isProofedHash(
                unProofedInputHash
            )).to.equal(false);
        });

        it("should return true for isProofedHash when inputHash is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs, proof);

            const proofedInputHash: string = secondHash(inputs);

            expect(await nearBlockVerification.isProofedHash(
                proofedInputHash
            )).to.equal(true);
        });

        it("should set verifier correctly", async function () {
            expect(await nearBlockVerification.getVerifier()).to.equal(verifier.address);

            const verifierFactory = await ethers.getContractFactory("Verifier");
            let newVerifier = await verifierFactory.deploy();
            await newVerifier.deployed();

            await nearBlockVerification.setVerifier(newVerifier.address);

            expect(await nearBlockVerification.getVerifier()).to.equal(newVerifier.address);
        });

        it("should emit ProofVerifiedAndSaved event", async () => {
          await expect(
              nearBlockVerification.verifyAndSaveProof(inputs, proof)
          )
              .to.emit(nearBlockVerification, "ProofVerifiedAndSaved")
        })

        it("should emit CompressedProofVerifiedAndSaved event", async () => {
          compressedProof = await verifier.compressProof(proof);
          await expect(
              nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof)
          )
              .to.emit(nearBlockVerification, "CompressedProofVerifiedAndSaved")
        })
    });
});


