// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Verifier} from "../src/Verifier.sol";
import {NearBlockVerification} from "../src/NearBlockVerification.sol";

contract NearBlockVerificationDeploymentScript is Script {
    address public verifierAddress;

    function setUp() public {
        verifierAddress = vm.envAddress("VERIFIER");
    }

    function run() public {
        Verifier verifier = Verifier(verifierAddress);

        NearBlockVerification nearBlockVerification = new NearBlockVerification();
        nearBlockVerification.initialize(address(verifier));
        console.log("NearBlockVerification deployed to:", address(nearBlockVerification));

        vm.broadcast();
    }
}
