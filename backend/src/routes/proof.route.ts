import express from "express";
import ProofController from "../controllers/proof.controller";
import path from "path";

const router = express.Router();

router.post("/generate-proof", ProofController.generateProof);
router.use("/proofs", express.static(path.join('/app/proofs')))
router.get("/proof-status",  ProofController.getProofStatus)
router.get("/health",  ProofController.health)

export default router;
