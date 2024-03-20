import {ethers} from "hardhat";
import "@nomiclabs/hardhat-etherscan";
import {assert, expect} from "chai";

// const crypto = require('crypto');

const fs = require('fs');

function secondHash(array: number[]): string {
    // convert last 8 elements of the array to hex values
    let hexValues: string[] = array.slice(8, 16).map(value => {
        const buffer = Buffer.alloc(4);
        buffer.writeUInt32BE(value, 0);
        return buffer.toString('hex');
    });

    // join all hex values into one string
    return '0x' + hexValues.join('');
}

describe("VerifierWith16Inputs", function () {
    let verifier;
    let nearBlockVerification;
    let inputs1, inputs2, proof1, proof2;
    let tx, gasUsed;
    let compressedProof1, compressedProof2;

    beforeEach(async () => {
        const verifierFactory = await ethers.getContractFactory("VerifierWith16Inputs");
        verifier = await verifierFactory.deploy();
        await verifier.deployed();

        let fileData = fs.readFileSync('test/proof_with_16_inputs_01.json', 'utf-8');
        let dataParsed = JSON.parse(fileData);
        inputs1 = dataParsed.inputs;
        proof1 = dataParsed.proof;

//         console.log("inputs1: ", inputs1);
//         console.log("proof1:", proof1);

        fileData = fs.readFileSync('test/proof_with_16_inputs_01.json', 'utf-8');
        dataParsed = JSON.parse(fileData);
        inputs2 = dataParsed.inputs;
        proof2 = dataParsed.proof;
    });

    it("should successfully execute the verifyProof request", async function () {
        await verifier.verifyProof(proof1, inputs1);
        await verifier.verifyProof(proof2, inputs2);
    });

    it("should successfully execute the verifyCompressedProof request", async function () {
        compressedProof1 = await verifier.compressProof(proof1)
        await verifier.verifyCompressedProof(compressedProof1, inputs1);

        compressedProof2 = await verifier.compressProof(proof2)
        await verifier.verifyCompressedProof(compressedProof2, inputs2);
    });

    describe("NearBlockVerificationWith16Inputs", function () {
        beforeEach(async () => {
            const NearBlockVerification = await ethers.getContractFactory("NearBlockVerificationWith16Inputs");
            nearBlockVerification = await NearBlockVerification.deploy(verifier.address);
            await nearBlockVerification.deployed();
        });

        it("should successfully execute the verifyAndSaveProof request", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs1, proof1);
        });

        it("should successfully execute the verifyAndSaveCompressedProof request", async function () {
            compressedProof2 = await verifier.compressProof(proof2);
            await nearBlockVerification.verifyAndSaveCompressedProof(inputs2, compressedProof2);
        });

        it("should return false for isProofed when input is not proofed", async function () {
            const unProofedInput = ["3664410971","1073907312","4177792513","2264873612","214675011","3219998602","2865816742","4151165762"];

            expect(await nearBlockVerification.isProofed(
                unProofedInput
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(0, 8)
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(8, 16)
            )).to.equal(false);
        });

        it("should return true for isProofed when input is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs1, proof1);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(8, 16)
            )).to.equal(true);
        });

        it("should correctly convert array to hash", async function () {
            let proofedInputHashBytes1: string = secondHash(inputs1);

            expect(await nearBlockVerification.toHash(
                inputs1.slice(8, 16),
            )).to.equal(proofedInputHashBytes1);

            let proofedInputHashBytes2: string = secondHash(inputs2);

            expect(await nearBlockVerification.toHash(
                inputs2.slice(8, 16),
            )).to.equal(proofedInputHashBytes2);
        });

        it("should return false for isProofedHash when inputHash is not proofed", async function () {
            const unProofedInputHash: string = "0xbc23058485c30c426caaf283decba76ddb675ffae9d53bfa1f189889518df031";

            expect(await nearBlockVerification.isProofedHash(
                unProofedInputHash
            )).to.equal(false);
        });

        it("should return true for isProofedHash when inputHash is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs2, proof2);

            const proofedInputHash: string = secondHash(inputs2);

            expect(await nearBlockVerification.isProofedHash(
                proofedInputHash
            )).to.equal(true);
        });

        it("should set verifier correctly", async function () {
            expect(await nearBlockVerification._verifier()).to.equal(verifier.address);

            const verifierFactory = await ethers.getContractFactory("VerifierWith16Inputs");
            let newVerifier = await verifierFactory.deploy();
            await newVerifier.deployed();

            await nearBlockVerification.setVerifier(newVerifier.address);

            expect(await nearBlockVerification._verifier()).to.equal(newVerifier.address);
        });
    });

    describe("NearBlockVerificationWith16InputsIA", function () {
        beforeEach(async () => {
            const NearBlockVerification = await ethers.getContractFactory("NearBlockVerificationWith16InputsIA");
            nearBlockVerification = await NearBlockVerification.deploy(verifier.address);
            await nearBlockVerification.deployed();
        });

        it("should successfully execute the verifyAndSaveProof request", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs1, proof1);
        });

        it("should successfully execute the verifyAndSaveCompressedProof request", async function () {
            compressedProof2 = await verifier.compressProof(proof2);
            await nearBlockVerification.verifyAndSaveCompressedProof(inputs2, compressedProof2);
        });

        it("should return false for isProofed when input is not proofed", async function () {
            const unProofedInput = ["3664410971","1073907312","4177792513","2264873612","214675011","3219998602","2865816742","4151165762"];

            expect(await nearBlockVerification.isProofed(
                unProofedInput
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(0, 8)
            )).to.equal(false);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(8, 16)
            )).to.equal(false);
        });

        it("should return true for isProofed when input is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs1, proof1);

            expect(await nearBlockVerification.isProofed(
                inputs1.slice(8, 16)
            )).to.equal(true);
        });

        it("should correctly convert array to hash", async function () {
            let proofedInputHashBytes1: string = secondHash(inputs1);

            expect(await nearBlockVerification.toHash(
                inputs1.slice(8, 16),
            )).to.equal(proofedInputHashBytes1);

            let proofedInputHashBytes2: string = secondHash(inputs2);

            expect(await nearBlockVerification.toHash(
                inputs2.slice(8, 16),
            )).to.equal(proofedInputHashBytes2);
        });

        it("should return false for isProofedHash when inputHash is not proofed", async function () {
            const unProofedInputHash: string = "0xbc23058485c30c426caaf283decba76ddb675ffae9d53bfa1f189889518df031";

            expect(await nearBlockVerification.isProofedHash(
                unProofedInputHash
            )).to.equal(false);
        });

        it("should return true for isProofedHash when inputHash is proofed", async function () {
            await nearBlockVerification.verifyAndSaveProof(inputs2, proof2);

            const proofedInputHash: string = secondHash(inputs2);

            expect(await nearBlockVerification.isProofedHash(
                proofedInputHash
            )).to.equal(true);
        });

        it("should set verifier correctly", async function () {
            expect(await nearBlockVerification._verifier()).to.equal(verifier.address);

            const verifierFactory = await ethers.getContractFactory("VerifierWith16Inputs");
            let newVerifier = await verifierFactory.deploy();
            await newVerifier.deployed();

            await nearBlockVerification.setVerifier(newVerifier.address);

            expect(await nearBlockVerification._verifier()).to.equal(newVerifier.address);
        });
    });
});


