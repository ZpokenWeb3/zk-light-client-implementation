import * as fs from 'fs';

// eslint-disable-next-line
export const goApiRequest = async (hexEncodedInputBytes: string): Promise<any> => {
  const url = 'http://gnark_wrapper:8010/proof';

  const current_block_proofData = await fs.promises.readFile(
    `/app/proofs/${hexEncodedInputBytes}/gnark/current_block_proof.json`,
    'utf8',
  );
  const verifier_only_circuit_dataData = await fs.promises.readFile(
    `/app/proofs/${hexEncodedInputBytes}/gnark/current_block_vd.json`,
    'utf8',
  );

  const proofWithPisBytes = Buffer.from(current_block_proofData, 'utf8');
  const verifierOnlyCircuitBytes = Buffer.from(verifier_only_circuit_dataData, 'utf8');

  const data = {
    id: 'req_bytes',
    proofWithPis: [...proofWithPisBytes],
    verifierData: [...verifierOnlyCircuitBytes],
  };

  console.log('Go service request', data);

  let response;
  await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then(response => response.json())
    .then(data => {
      console.log('Response from go service:', data);
      response = data;
      return data;
    })
    .catch(error => {
      console.error('Error from go service::', error);
    });

  return response;
};
