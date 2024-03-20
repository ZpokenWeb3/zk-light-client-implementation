## Message Proof of Inclusion for Near Blockchain

#### Let's take a look at the contract [first.zpoken-vault-contract.testnet](https://testnet.nearblocks.io/address/first.zpoken-vault-contract.testnet), which stores the desired information related to the bridge functioning

The structure of the contract storage is the following

```rust
   #[near_bindgen]
   #[derive(BorshDeserialize, BorshSerialize)]
   pub struct VaultContract {
       // depositor_addr -> BridgeInfo
       bridge_info: UnorderedMap<AccountId, BridgeInfo>,
   
       receiver_addr: AccountId,
       asset_id: AccountId,
       deposited_amount: Balance,
   
       count_param: Balance,
   }
   
   #[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
   #[serde(crate = "near_sdk::serde")]
   pub struct BridgeInfo {
       pub receiver_addr: AccountId,
       pub asset_id: AccountId,
       pub deposited_amount: Balance,
   }
```

and the respective deposit function

```rust
   #[near_bindgen]
   impl VaultContract {
       pub fn deposit(
           &mut self,
           receiver_addr: AccountId,
           asset_id: AccountId,
           token_amount: WBalance,
       ) -> PromiseOrValue<WBalance> {
           self.count_param += 1;
   
           self.receiver_addr = receiver_addr.clone();
           self.deposited_amount = token_amount.0.clone();
           self.asset_id = asset_id.clone();
   
           let sender_id = env::signer_account_id();
   
           self.bridge_info.insert(
               &sender_id,
               &BridgeInfo {
                   receiver_addr,
                   asset_id,
                   deposited_amount: token_amount.0,
               },
           );
   
           PromiseOrValue::Value(U128::from(0))
       }
   }

```

The inner algorithm for proof of inclusion the following:

1) Configure account in config.json file 
   
```json
   {
   "account": "first.zpoken-vault-contract.testnet",
   "network": 0 // 0 - for TESTNET, 1 for MAINNET
   }
```

2) Make a sample deposit transaction https://testnet.nearblocks.io/txns/8zcsAgUZUcf3VnZpjAgKrVRfkFdzPsYNaNk7AEXvXVtF  to fill up the desired storage slots with an information we want to proove.


3) Get storage key-values for the contract and respective proof for that through RPC command

```
   http post https://rpc.testnet.near.org jsonrpc=2.0 id=dontcare method=query \
   params:='{
   "request_type": "view_state",
   "finality": "final",
   "account_id": "first.zpoken-vault-contract.testnet",
   "prefix_base64": "",
   "include_proof": true
   }'
```

4) Having result that can be deserialized into ViewStateResult (note that this is an example call, latest query might be
   different due to rapid block production in Near). There is inner  optimization so it might store it all together in one slot for the sake of saving memory

```rust
   #[serde_as]
   #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
   pub struct ViewStateResult {
       pub values: Vec<StateItem>,
       #[serde_as(as = "Vec<Base64>")]
       #[serde(default, skip_serializing_if = "Vec::is_empty")]
       pub proof: Vec<Arc<[u8]>>,
   }
   
   /// Item of the state, key and value are serialized in base64 and proof for inclusion of given state item.
   #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
   pub struct StateItem {
       pub key: StoreKey,
       pub value: StoreValue,
   }
```

```json
   {
      "id": "dontcare",
      "jsonrpc": "2.0",
      "result": {
         "block_hash": "6Rd1BBdRdBkccCsWVaGpSmLWttjErk47DxvFzXeqg9r1",
         "block_height": 139263676,
         "proof": [
            "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",
            "AcAAlItbZsiaJKhUMZ3LsPjhkNAONA+ENlHP/CN19EazmFnHMLvRu+SNnedHWHkYAa3UC4WvntUuncvkadQpTW6Lp8v9AQAAAAAA",
            "ARQEGB7RURXKQ6MYk9eTac2iTZz+p8wxi3IUeFz/Z5UJrQ6YDDq1cBqSTVGqyg8fBtUvYvzb4NCrdnFZbdW+TroBbmAwnN6bsmOp0WV+2g7PBB7L/GT+68aTH7yIbSTCPPycxQkAAAAAAAA=",
            "AwEAAAAXDKgVftYhKy78ko6GH2Wt1CXqv1ovVSxgNyiYC7igYDtRCAAAAAAAAA==",
            "AQECy3rtrxjMU9s+nlON9LHYXy+QK5s3lxbYjfOQrpY9ECzcmmFTODle4sx+jC8w/dY1cL47BiOcq9wb+1hyL/ZF4x0IAAAAAAAA",
            "ACIAAAAgb2tlbi12YXVsdC1jb250cmFjdC50ZXN0bmV0LFNUQVRFYAAAAJyRk9PVv9HSohIZhudMgXkrj/mxPGYRPYjoaGzWyLF+CAEAAAAAAAA="
         ],
         "values": [
            {
               "key": "U1RBVEU=",
               "value": "HQAAAHpwb2tlbi12YXVsdC1jb250cmFjdC50ZXN0bmV0DQAAAHJlY2VpdmVyLm5lYXIKAAAAYXNzZXQubmVhcgAAANB5AKE/eVx2BgAAAAACAAAAAAAAAAAAAAAAAAAA"
            }
         ]
      }
   }
```

5) Have to ensure that the proof is valid by checking key-value existence through near-core verification logic. Proof
   itself is all the nodes visited, that store the different pieces of a contract's / account's metadata. near-core
   verification logic is the following

```rust
   pub(crate) fn verify(
       &self,
       state_root: &StateRoot,
       account_id: &AccountId,
       key: &[u8],
       expected: Option<&[u8]>,
   ) -> bool {
       let query = trie_key_parsers::get_raw_prefix_for_contract_data(account_id, key);
       let mut key = NibbleSlice::new(&query);
   
       let mut expected_hash = state_root;
       while let Some(node) = self.nodes.get(expected_hash) {
           match &node.node {
               RawTrieNode::Leaf(node_key, value) => {
                   let nib = &NibbleSlice::from_encoded(&node_key).0;
                   return if &key != nib {
                       expected.is_none()
                   } else {
                       expected.map_or(false, |expected| value == expected)
                   };
               }
               RawTrieNode::Extension(node_key, child_hash) => {
                   expected_hash = child_hash;
   
                   // To avoid unnecessary copy
                   let nib = NibbleSlice::from_encoded(&node_key).0;
                   if !key.starts_with(&nib) {
                       return expected.is_none();
                   }
                   key = key.mid(nib.len());
               }
               RawTrieNode::BranchNoValue(children) => {
                   if key.is_empty() {
                       return expected.is_none();
                   }
                   match children[key.at(0)] {
                       Some(ref child_hash) => {
                           key = key.mid(1);
                           expected_hash = child_hash;
                       }
                       None => return expected.is_none(),
                   }
               }
               RawTrieNode::BranchWithValue(value, children) => {
                   if key.is_empty() {
                       return expected.map_or(false, |exp| value == exp);
                   }
                   match children[key.at(0)] {
                       Some(ref child_hash) => {
                           key = key.mid(1);
                           expected_hash = child_hash;
                       }
                       None => return expected.is_none(),
                   }
               }
           }
       }
       false
   }
```

6) We will iterate through all the key-value pairs in the state and verify that the proof is valid for them and check
   that there if a respective amount of proofs for each key-value


7) We proved that arbitrary data was indeed included in the smart contract state.

8) Now we want to ensure that it is included in Near Blockchain itself. So we will iterate through all the previous blocks to see in what chunk out account's metadata lives in. Respective code for that is the following:


```rust
loop {
            let block_request = BlockRequestOptionTwo {
                jsonrpc: "2.0",
                id: "dontcare",
                method: "block",
                params: BlockParamBlockHeight {
                    block_id: block_height_iter.clone(),
                },
            };

            if client.post(rpc_url)
                .json(&block_request)
                .send()
                .await?.json::<BlockResponse>().await.is_err() {
                block_height_iter -= 1;
                continue;
            } else {
                let block_response: BlockResponse = client.post(rpc_url)
                    .json(&block_request)
                    .send()
                    .await?.json().await?
                    ;

                for chunk in block_response.result.chunks.iter() {
                    if chunk.prev_state_root == state_root {
                        writeln!(file, "{}", format!("success prev_state_root {:?} for the block {:?}", chunk.prev_state_root, block_response.result.header.height)).expect("Unable to write to file");
                        println!("Script finished!");

                        exit(0);
                    }
                }
            }


            block_height_iter -= 1;
        }
```

9) And success, the result is shown in result_with_proofs.txt that means that the block with a hash of EhYzmehyFZo3sxVjJjkfrhtvgbYbWcNnTwUm9KmfgyDg has a previous state root, that is equal to ours state root proof. So it means that our value indeed included in the blockchain
```

Key: StoreKey([83, 84, 65, 84, 69])
Value: StoreValue([29, 0, 0, 0, 122, 112, 111, 107, 101, 110, 45, 118, 97, 117, 108, 116, 45, 99, 111, 110, 116, 114, 97, 99, 116, 46, 116, 101, 115, 116, 110, 101, 116, 13, 0, 0, 0, 114, 101, 99, 101, 105, 118, 101, 114, 46, 110, 101, 97, 114, 10, 0, 0, 0, 97, 115, 115, 101, 116, 46, 110, 101, 97, 114, 0, 0, 0, 208, 121, 0, 161, 63, 121, 92, 118, 6, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
State Root: EhYzmehyFZo3sxVjJjkfrhtvgbYbWcNnTwUm9KmfgyDg
Block Hash: "AUZ8KGc3yGPAiWcpo2fJ1GgkbR9VE68D2TjkYwEAoo8R"
----------------------------------------------------------
success prev_state_root "EhYzmehyFZo3sxVjJjkfrhtvgbYbWcNnTwUm9KmfgyDg" for the block 139406234
```




