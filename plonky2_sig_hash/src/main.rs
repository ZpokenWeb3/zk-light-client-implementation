use anyhow::Result;
use log::LevelFilter;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_sig_hash::sig_hash_circuit::{
    aggregation_two, hash_circuit_proof, sig_circuit_proof, verification, make_hash, decode_hex
};
use std::fs::OpenOptions;
use std::io::Write;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub const PK: [&str; 5] = [
    "EF3E2F087EE8CB7A457F346BBEBE552AB88BD476C880E979C964BA53F9CEFC92",
    "DA7C178CFDB5A241DB0347BA88BF748049567E23E9D96724E43672EAC787FEAB",
    "A2B0D2A2EC6F73AB8DCADA1CF90D8AA34A39799FF211E1B3911527FA753AF692",
    "E26D24EE14F6C65AD861B86ADEA6D28E537D6509EA604C0BA5BA61B44DF60D6E",
    "E3C0377BC53A1C07BEA75D6B1F72FBCB91E1327CE115BF558BF411A2974D9E12",
];
pub const SIG : [&str; 5] = [
    "F3ACF81D9C44DC7CBB5ABE692B79E24E8859B01858CDB2BB1763DB6B7218914861C999676D224406E1C44C3722D0AF1BA94CC59ED63CB37D57DE929BEC2BA800",
    "79777D5DAE3997A87CC68262FB0C8A023EDAD052F97BD49FEAB3C4E5F93464B60E1EE4D7CDD335B0ACA4509B761B49A13A2FE0FAF66BE9C5D13CB36443C02406",
    "35F2D39E124038087B2CFB5D4E0A03656FC082A5B9489DDFEFEB7E2FEC9AA43CE1124694E97F386F8B3931DCBABF5676865F248EA132C00B30D96076C8FD380D",
    "3267B4A4E9A10A0C37FB774809D49D7977AD8CEBAE9677E02177DED1484C130646955D34D65BAB7A656F2C56E9F9641EC1A457EEE312363CE892FF17F229FD04",
    "C9E0B1F68A5A6BA01D623EA8DB8A0A8569EBE49FA5CF06D24D3871CA21D2E4942AC05E99BDFBF04D9AEECCCD5F9EF1DB94F14B423760C857FECE9F688B40370B"
];

pub fn write_proof_to_file(
    file_name: &str,
    p1: ProofWithPublicInputs<F, C, D>,
    p2: ProofWithPublicInputs<F, C, D>,
    p3: ProofWithPublicInputs<F, C, D>,
) -> Result<(), std::io::Error> {
    write_to_file(file_name.trim(), &(p1).to_bytes().len().to_ne_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), &(p1).to_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), &p2.to_bytes().len().to_ne_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), &p2.to_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), &(p3).to_bytes().len().to_ne_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), &(p3).to_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    Ok(())
}

pub fn write_to_file(file_name: &str, data: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(file_name)?;
    file.write_all(data)?;
    Ok(())
}
pub fn create_file(nonce: usize) -> String {
    let file_name = "data".to_owned() + &(nonce.to_string()) + ".bin";
    file_name
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;

    let mut nonce: usize = 0;
    // nonce as string is the message to be hashed
    let mut msg: String = nonce.to_string();
    println!("Msg: {}", msg);
    let mut hashes: Vec<String> = Vec::new();
    // tmp circuit and proof
    let (mut d, mut p): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // tmp aggregated sig & hash
    let (mut ag_d, mut ag_p): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // chain of aggregated proofs for hashes
    let mut proof_hash: Vec<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> = Vec::new();
    // chain of aggregated proofs for signatures & hashes
    let mut proof_sh: Vec<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> = Vec::new();
    hashes.push(make_hash(&(msg.as_bytes())));
    println!("Hash: {}", hashes[nonce]);
    // proof for hash
    proof_hash.push(hash_circuit_proof(
        msg.as_bytes(),
        decode_hex(&hashes[nonce])?.as_slice(),
    ));
    println!("Proof hash size: {}", proof_hash[nonce].1.to_bytes().len());
    // proof for sig
    (d, p) = sig_circuit_proof(
        decode_hex(&hashes[nonce])?.as_slice(),
        decode_hex(&SIG[nonce].to_string())?.as_slice(),
        decode_hex(&PK[nonce].to_string())?.as_slice(),
    );
    println!("Proof sig size: {}", p.to_bytes().len());
    // proof for hash & sig
    proof_sh.push(aggregation_two(
        (&proof_hash[nonce].0, &proof_hash[nonce].1),
        (&d, &p),
    )?);
    println!(
        "Proof hash & sig size: {}",
        proof_sh[nonce].1.to_bytes().len()
    );
    let mut file_name = create_file(nonce);
    write_to_file(file_name.trim(), msg.as_bytes())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_to_file(file_name.trim(), decode_hex(&hashes[nonce])?.as_slice())
        .map_err(|err| println!("{:?}", err))
        .ok();
    write_proof_to_file(
        file_name.trim(),
        proof_hash[nonce].1.clone(),
        p.clone(),
        proof_sh[nonce].1.clone(),
    )
    .map_err(|err| println!("{:?}", err))
    .ok();
    // make a chain of five proofs
    nonce += 1;
    while nonce < 5 {
        msg = hashes[nonce - 1].clone() + &nonce.to_string();
        println!("Msg: {}", msg);
        hashes.push(make_hash(&(msg.as_bytes())));
        println!("Hash: {}", hashes[nonce]);
        // proof for hash
        proof_hash.push(hash_circuit_proof(
            msg.as_bytes(),
            decode_hex(&hashes[nonce])?.as_slice(),
        ));
        println!("Proof hash size: {}", proof_hash[nonce].1.to_bytes().len());
        // proof for sig
        (d, p) = sig_circuit_proof(
            decode_hex(&hashes[nonce])?.as_slice(),
            decode_hex(&SIG[nonce].to_string())?.as_slice(),
            decode_hex(&PK[nonce].to_string())?.as_slice(),
        );
        println!("Proof sig size: {}", p.to_bytes().len());
        // proof for hash & sig of current block
        (ag_d, ag_p) =
            aggregation_two((&proof_hash[nonce].0, &proof_hash[nonce].1), (&d, &p)).unwrap();
        // aggregation of current & previous blocks
        proof_sh.push(aggregation_two(
            (&proof_sh[nonce - 1].0, &proof_sh[nonce - 1].1),
            (&ag_d, &ag_p),
        )?);
        println!(
            "Proof hash & sig size: {}",
            proof_sh[nonce].1.to_bytes().len()
        );
        file_name = create_file(nonce);
        write_to_file(file_name.trim(), msg.as_bytes())
            .map_err(|err| println!("{:?}", err))
            .ok();
        write_to_file(file_name.trim(), decode_hex(&hashes[nonce])?.as_slice())
            .map_err(|err| println!("{:?}", err))
            .ok();
        write_proof_to_file(
            file_name.trim(),
            proof_hash[nonce].1.clone(),
            p.clone(),
            proof_sh[nonce].1.clone(),
        )
        .map_err(|err| println!("{:?}", err))
        .ok();

        nonce += 1;
    }
    verification((&proof_sh[nonce - 1].0, &proof_sh[nonce - 1].1))
}
