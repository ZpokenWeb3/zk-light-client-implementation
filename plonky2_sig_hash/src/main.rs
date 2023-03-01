use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_test_case4::sig_hash_circuit::{
    aggregation_three, aggregation_two, decode_hex, hash_circuit_proof, make_hash,
    sig_circuit_proof,
};

use ed25519_compact::*;

use std::collections::HashMap;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone)]
pub struct Block {
    nonce: usize,
    height: usize,
    prev_hash: String,
    hash: String,
    epock_id: String,
    sig: Signature,
    v_sig: [Signature; 3],
}
#[derive(Clone)]
pub struct EpochBlock {
    nonce: usize,
    height: usize,
    prev_hash: String,
    hash: String,
    epock_id: String,
    sig: Signature,
    v_sig: [Signature; 3],
    v_pk: HashMap<usize, PublicKey>, //?
}
impl EpochBlock {
    fn get_v_pk(&self) -> HashMap<usize, PublicKey> {
        self.v_pk.clone()
    }
}
#[derive(Clone)]
pub enum BlockType {
    Block(Block),
    EpochBlock(EpochBlock),
}
impl BlockType {
    fn get_nonce(&self) -> usize {
        match *self {
            BlockType::Block(ref s) => s.nonce,
            BlockType::EpochBlock(ref p) => p.nonce,
        }
    }
    fn get_height(&self) -> usize {
        match *self {
            BlockType::Block(ref s) => s.height,
            BlockType::EpochBlock(ref p) => p.height,
        }
    }
    fn get_prev_hash(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.prev_hash.clone(),
            BlockType::EpochBlock(ref p) => p.prev_hash.clone(),
        }
    }
    fn get_hash(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.hash.clone(),
            BlockType::EpochBlock(ref p) => p.hash.clone(),
        }
    }
    fn get_epock_id(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.epock_id.clone(),
            BlockType::EpochBlock(ref p) => p.epock_id.clone(),
        }
    }
    fn get_sig(&self) -> Signature {
        match *self {
            BlockType::Block(ref s) => s.sig,
            BlockType::EpochBlock(ref p) => p.sig,
        }
    }
    fn get_v_sig(&self) -> [Signature; 3] {
        match *self {
            BlockType::Block(ref s) => s.v_sig,
            BlockType::EpochBlock(ref p) => p.v_sig,
        }
    }
    fn get_v_pk(&self) -> Option<HashMap<usize, PublicKey>> {
        match *self {
            BlockType::EpochBlock(ref p) => Some(p.v_pk.clone()),
            BlockType::Block(_) => Option::None,
        }
    }
}

pub trait Data {
    fn new() -> Self
    where
        Self: Sized;
}
impl Data for Block {
    fn new() -> Block {
        Block {
            nonce: 0,
            height: 0,
            prev_hash: String::new(),
            hash: String::new(),
            epock_id: String::new(),
            sig: Signature::new([0; 64]),
            v_sig: [Signature::new([0; 64]); 3],
        }
    }
}
impl Data for EpochBlock {
    fn new() -> EpochBlock {
        EpochBlock {
            nonce: 0,
            height: 0,
            prev_hash: String::new(),
            hash: String::new(),
            epock_id: String::new(),
            sig: Signature::new([0; 64]),
            v_sig: [Signature::new([0; 64]); 3],
            v_pk: HashMap::new(),
        }
    }
}
pub fn print(v: &[u8]) {
    for i in v.iter() {
        print!("{:x}", i);
    }
    println!();
}
pub fn print_data(b: Vec<BlockType>) {
    println!("Number of blocks: {}", b.len());
    for i in b.iter() {
        println!(
            "\nnonce: {}\nheight: {}\nprev_hash: {}\nhash: {}\nepock_id: {}",
            i.get_nonce(),
            i.get_height(),
            i.get_prev_hash(),
            i.get_hash(),
            i.get_epock_id()
        );
        print!("sig: ");
        print(i.get_sig().as_slice());
        println!("v_sig: ");
        for j in i.get_v_sig().iter() {
            print(j.as_slice());
        }
        match i {
            BlockType::Block(_) => (),
            BlockType::EpochBlock(s) => {
                println!("v_pk: ");
                for j in s.get_v_pk().iter() {
                    print!("{}: ", j.0);
                    print(j.1.as_slice());
                }
            }
        }
    }
}

pub fn main() {
    // generate keys for users
    let mut users: HashMap<u32, (PublicKey, SecretKey)> = HashMap::new();
    let mut keypair: KeyPair;
    for i in 0..3 {
        keypair = KeyPair::from_seed(Seed::generate());
        users.insert(i, (keypair.pk, keypair.sk));
    }
    let mut msg: String;
    let mut blockchain: Vec<BlockType> = Vec::new();
    let mut epoch_block: EpochBlock = EpochBlock::new();
    let mut block: Block = Block::new();
    let mut proofchain: Vec<(
        (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
        (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    )> = Vec::new();
    // circuit and proof for current hash
    let (mut c_hash, mut p_hash): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // circuit and proof for current signature
    let (mut c_sig, mut p_sig): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // circuit and proof for block verifiers
    let (mut prod_c, mut prod_p): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // tmp aggregated hash & signature
    let (mut ag_c, mut ag_p): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // epock proof
    let (mut epoch_c, mut epoch_p): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    for i in 0..3 {
        match i % 3 {
            0 => {
                epoch_block.nonce = i;
                epoch_block.height = 3;
                for j in 0..users.len() {
                    epoch_block
                        .v_pk
                        .insert(j, users.get(&(j as u32)).unwrap().0);
                }
                if i != 0 {
                    epoch_block.prev_hash = blockchain[i - 1].get_hash().clone();
                }
                msg = epoch_block.prev_hash.clone() + &i.to_string();
                epoch_block.hash = make_hash(msg.as_bytes());
                epoch_block.epock_id = epoch_block.hash.clone();
                epoch_block.sig = users
                    .get(&((i % users.len()) as u32))
                    .unwrap()
                    .1
                    .sign(&decode_hex(&epoch_block.hash).unwrap(), None);
                if i != 0 {
                    for j in 0..users.len() {
                        epoch_block.v_sig[j] = users
                            .get(&(j as u32))
                            .unwrap()
                            .1
                            .sign(&decode_hex(&epoch_block.hash).unwrap(), None);
                    }
                }
                blockchain.push(BlockType::EpochBlock(epoch_block.clone()));
            }
            _ => {
                block.nonce = i;
                block.height = i % users.len();
                block.prev_hash = blockchain[i - 1].get_hash();
                msg = block.prev_hash.clone() + &i.to_string();
                block.hash = make_hash(msg.as_bytes());
                block.epock_id = blockchain[i - 1].get_epock_id();
                block.sig = users
                    .get(&((i % users.len()) as u32))
                    .unwrap()
                    .1
                    .sign(&decode_hex(&block.hash).unwrap(), None);
                for j in 0..users.len() {
                    block.v_sig[j] = users
                        .get(&(j as u32))
                        .unwrap()
                        .1
                        .sign(&decode_hex(&block.hash).unwrap(), None);
                }
                blockchain.push(BlockType::Block(block.clone()));
            }
        }
    }
    print_data(blockchain.clone());
    epoch_block = EpochBlock::new();
    epoch_block.v_pk = blockchain[0].get_v_pk().unwrap().clone();
    msg = blockchain[0].get_prev_hash().clone() + &blockchain[0].get_nonce().to_string();
    (epoch_c, epoch_p) = hash_circuit_proof(
        msg.as_bytes(),
        &decode_hex(&blockchain[0].get_hash()).unwrap(),
    );
    for i in 0..blockchain.len() {
        msg = blockchain[i].get_prev_hash().clone() + &blockchain[i].get_nonce().to_string();
        println!("Msg: {}", msg);
        (c_hash, p_hash) = hash_circuit_proof(
            msg.as_bytes(),
            &decode_hex(&blockchain[i].get_hash()).unwrap(),
        );
        if blockchain[i].get_height() == 3 {
            (epoch_c, epoch_p) = hash_circuit_proof(
                msg.as_bytes(),
                &decode_hex(&blockchain[i].get_hash()).unwrap(),
            );
        }
        println!("Proof hash sz: {}", p_hash.to_bytes().len());
        (c_sig, p_sig) = sig_circuit_proof(
            &decode_hex(&blockchain[i].get_hash()).unwrap(),
            blockchain[i].get_sig().as_slice(),
            epoch_block.v_pk.get(&(i % users.len())).unwrap().as_slice(),
        );
        println!("Proof signature sz: {}", p_hash.to_bytes().len());
        (ag_c, ag_p) = aggregation_two((&c_hash, &p_hash), Some((&c_sig, &p_sig))).unwrap();
        if i != 0 {
            (ag_c, ag_p) = aggregation_three(
                (&epoch_c, &epoch_p),
                (&proofchain[i - 1].0 .0, &proofchain[i - 1].0 .1),
                (&ag_c, &ag_p),
            )
            .unwrap();
        }
        if i != blockchain.len() - 1 {
            for j in 0..blockchain[i].get_v_sig().len() {
                (prod_c, prod_p) = sig_circuit_proof(
                    &decode_hex(&blockchain[i + 1].get_hash()).unwrap(),
                    blockchain[i + 1].get_v_sig()[j].as_slice(),
                    epoch_block.v_pk.get(&j).unwrap().as_slice(),
                );
                (ag_c, ag_p) = aggregation_two((&prod_c, &prod_p), Some((&ag_c, &ag_p))).unwrap();
            }
        }
        proofchain.push(((c_hash, p_hash), (ag_c, ag_p)));
        println!("Final proof sz: {}", proofchain[i].1 .1.to_bytes().len());
        if blockchain[i].get_height() == 3 && blockchain[i].get_nonce() != 0 {
            epoch_block = EpochBlock::new();
            epoch_block.v_pk = blockchain[i].get_v_pk().unwrap().clone();
        }
    }
}
