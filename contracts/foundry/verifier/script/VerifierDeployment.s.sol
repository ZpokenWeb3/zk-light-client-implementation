// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Verifier} from "../src/Verifier.sol";

contract VerifierDeploymentScript is Script {
    function setUp() public {}

    function run() public {
        Verifier verifier = new Verifier();
        console.log("Verifier deployed to:", address(verifier));

        vm.broadcast();
    }
}
