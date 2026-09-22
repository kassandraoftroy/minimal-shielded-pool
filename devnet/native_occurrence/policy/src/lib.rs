//! Bounded client-policy evidence. This is not full blockchain/RPC admission.
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use ethrex_blockchain::focil_profile2::{
        MAX_VALIDATION_CODE_BODIES, max_validation_code_bytes, profile2_candidate,
    };
    use ethrex_blockchain::mempool::{KeyedConcurrency, Mempool, keyed_concurrency_verdict};
    use ethrex_common::{
        Address, H256, U256,
        types::{
            Account, AccountState, ChainConfig, Code, CodeMetadata, Fork, MempoolTransaction,
            Transaction, frame_tx_nonce_manager, frame_tx_recent_root,
        },
        utils::keccak,
    };
    use ethrex_crypto::NativeCrypto;
    use ethrex_levm::{
        db::{Database, gen_db::GeneralizedDatabase},
        environment::{EVMConfig, Environment},
        errors::DatabaseError,
        tracing::LevmCallTracer,
        validation_observer::{CodeBudget, Profile2Surface, ValidationObserver},
        vm::{VM, VMType},
    };
    use rustc_hash::FxHashMap;
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
        str::FromStr,
        sync::Arc,
    };

    struct EmptyDatabase;
    impl Database for EmptyDatabase {
        fn get_account_state(&self, _: Address) -> Result<AccountState, DatabaseError> {
            Ok(AccountState::default())
        }
        fn get_storage_value(&self, _: Address, _: H256) -> Result<U256, DatabaseError> {
            Ok(U256::zero())
        }
        fn get_block_hash(&self, _: u64) -> Result<H256, DatabaseError> {
            Ok(H256::zero())
        }
        fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
            Ok(ChainConfig::default())
        }
        fn get_account_code(&self, _: H256) -> Result<Code, DatabaseError> {
            Ok(Code::from_bytecode(Bytes::new(), &NativeCrypto))
        }
        fn get_code_metadata(&self, _: H256) -> Result<CodeMetadata, DatabaseError> {
            Ok(CodeMetadata { length: 0 })
        }
    }
    fn addr(s: &str) -> Address {
        Address::from_str(s).unwrap()
    }
    fn quantity(s: &str) -> U256 {
        if let Some(s) = s.strip_prefix("0x") {
            U256::from_str_radix(s, 16).unwrap()
        } else {
            U256::from_dec_str(s).unwrap()
        }
    }
    fn read_hex(path: &Path) -> Bytes {
        let s = fs::read_to_string(path).unwrap();
        hex::decode(s.trim().trim_start_matches("0x"))
            .unwrap()
            .into()
    }
    fn recent_root_code() -> Bytes {
        let source = include_str!(concat!(
            env!("ETHREX_SOURCE"),
            "/crates/vm/system_contracts.rs"
        ));
        let raw = source
            .split("pub const RECENT_ROOT_RUNTIME_BYTECODE: [u8; 345] = [")
            .nth(1)
            .unwrap()
            .split("];")
            .next()
            .unwrap();
        let code: Vec<u8> = raw
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap())
            .collect();
        assert_eq!(code.len(), 345);
        assert_eq!(
            format!("{:x}", keccak(&code)),
            "cd1cae00e1d37cf97195f9e716dfa1b9a804e36bb5d7726c4f2c50e2580275a5"
        );
        code.into()
    }
    fn manifest() -> (PathBuf, Value) {
        let root = std::env::var("POLICY_FIXTURES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
            });
        let data =
            serde_json::from_str(&fs::read_to_string(root.join("manifest.json")).unwrap()).unwrap();
        (root, data)
    }
    fn environment(manifest: &Value, tx: &Transaction, slot: u64) -> Environment {
        let mut env = Environment {
            origin: tx.sender(&NativeCrypto).unwrap(),
            gas_limit: tx.gas_limit(),
            block_gas_limit: manifest["block_gas_limit"].as_u64().unwrap_or(60_000_000),
            config: EVMConfig::new(Fork::Hegota, EVMConfig::canonical_values(Fork::Hegota)),
            chain_id: U256::from(manifest["chain_id"].as_u64().unwrap()),
            base_fee_per_gas: U256::from(manifest["base_fee"].as_u64().unwrap_or(1)),
            gas_price: tx
                .effective_gas_price(Some(manifest["base_fee"].as_u64().unwrap_or(1)))
                .unwrap(),
            tx_nonce: tx.nonce(),
            block_number: slot,
            timestamp: slot * 12,
            tx_max_priority_fee_per_gas: tx.max_priority_fee(),
            tx_max_fee_per_gas: tx.max_fee_per_gas(),
            tx_max_fee_per_blob_gas: tx.max_fee_per_blob_gas(),
            tx_blob_hashes: tx.blob_versioned_hashes(),
            base_blob_fee_per_gas: U256::one(),
            ..Default::default()
        };
        env.slot_number = U256::from(slot);
        env.config.slot_number = U256::from(slot);
        env
    }
    fn setup(root: &Path, manifest: &Value) -> GeneralizedDatabase {
        let mut cache = FxHashMap::default();
        for item in manifest["accounts"].as_array().unwrap() {
            let address = addr(item["address"].as_str().unwrap());
            let code = item["code"]
                .as_str()
                .map(|s| read_hex(&root.join(s)))
                .unwrap_or_default();
            let storage = item["storage"]
                .as_object()
                .map(|object| {
                    object
                        .iter()
                        .map(|(k, v)| {
                            (
                                H256::from(quantity(k).to_big_endian()),
                                quantity(v.as_str().unwrap()),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            cache.insert(
                address,
                Account::new(
                    quantity(item["balance"].as_str().unwrap()),
                    Code::from_bytecode(code, &NativeCrypto),
                    item["nonce"].as_u64().unwrap_or(0),
                    storage,
                ),
            );
        }
        for (address, code) in [
            (frame_tx_recent_root(), recent_root_code()),
            (
                frame_tx_nonce_manager(),
                Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]),
            ),
        ] {
            cache.insert(
                address,
                Account::new(
                    U256::zero(),
                    Code::from_bytecode(code, &NativeCrypto),
                    1,
                    FxHashMap::default(),
                ),
            );
        }
        let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(EmptyDatabase), cache);
        for step in manifest["setup"].as_array().unwrap() {
            let tx =
                Transaction::decode_canonical(&read_hex(&root.join(step["raw"].as_str().unwrap())))
                    .unwrap();
            let slot = step["slot_number"]
                .as_u64()
                .unwrap_or(manifest["slot_number"].as_u64().unwrap());
            let report = VM::new(
                environment(manifest, &tx, slot),
                &mut db,
                &tx,
                LevmCallTracer::disabled(),
                VMType::L1,
                &NativeCrypto,
                None,
            )
            .unwrap()
            .execute()
            .unwrap();
            assert!(
                report.is_success(),
                "setup {} failed: {:?}",
                step["raw"],
                report.result
            );
        }
        db
    }
    fn vector(root: &Path, filename: &str) -> Transaction {
        Transaction::decode_canonical(&read_hex(&root.join(filename))).unwrap()
    }
    fn prefix(
        root: &Path,
        manifest: &Value,
        tx: &Transaction,
        profile2: bool,
        inject_read: bool,
    ) -> Value {
        let Transaction::FrameTransaction(ft) = tx else {
            panic!("frame tx required")
        };
        let prefix = ft.validation_prefix().unwrap();
        let mut db = setup(root, manifest);
        if inject_read {
            // Negative control: execute a mapping-like SLOAD in the sender's
            // validation frame. Deliberately not a candidate implementation.
            let mut code = vec![0x7f];
            code.extend_from_slice(keccak(b"duplicate-output-membership").as_bytes());
            code.extend_from_slice(&[0x54, 0x50, 0x5f, 0x5f, 0xfd]);
            let replacement = Code::from_bytecode(code.into(), &NativeCrypto);
            db.current_accounts_state
                .get_mut(&ft.sender)
                .unwrap()
                .info
                .code_hash = replacement.hash;
            db.codes.insert(replacement.hash, replacement);
        }
        let mut observer = ValidationObserver::new(
            ft.sender,
            prefix.deploy_index,
            ethrex_common::types::frame_tx_expiry_verifier(),
        );
        observer.recent_root_verifier_frame = prefix.recent_root_index;
        observer.recent_root_address = frame_tx_recent_root();
        if profile2 {
            let chain_config = ChainConfig::default();
            observer.profile2 = Some(Profile2Surface {
                payer: ft.sender,
                slot_count: U256::from(chain_config.aa_vops_slot_count()),
            });
            observer.code_budget = Some(CodeBudget::new(
                MAX_VALIDATION_CODE_BODIES,
                max_validation_code_bytes(
                    &chain_config,
                    (manifest["slot_number"].as_u64().unwrap() + 1) * 12,
                ),
            ));
        }
        let slot = std::env::var("POLICY_SLOT")
            .ok()
            .map(|s| s.parse().unwrap())
            .unwrap_or(manifest["slot_number"].as_u64().unwrap() + 1);
        let mut vm = VM::new(
            environment(manifest, tx, slot),
            &mut db,
            tx,
            LevmCallTracer::disabled(),
            VMType::L1,
            &NativeCrypto,
            None,
        )
        .unwrap();
        let result = vm
            .run_frame_validation_prefix_with_observer(&prefix.frame_indices, observer)
            .unwrap();
        let verdict = keyed_concurrency_verdict(
            true,
            prefix.deploy_index.is_some(),
            !vm.validation_observer.touched_sender_slots.is_empty(),
            vm.validation_observer.read_legacy_nonce,
        );
        json!({"profile2_surface": profile2, "injected_mapping_read": inject_read,
            "prefix_gas": result.total_gas_used, "any_revert": result.any_revert,
            "payer": result.payer_address.map(|a| format!("{a:#x}")),
            "sender_slots": vm.validation_observer.touched_sender_slots.iter().map(|s| format!("{s:#x}")).collect::<Vec<_>>(),
            "read_legacy_nonce": vm.validation_observer.read_legacy_nonce,
            "violation": vm.validation_observer.violation.as_ref().map(|v| format!("{v:?}")),
            "keyed_concurrency": format!("{verdict:?}"),
            "loaded_code_bodies": vm.validation_observer.code_budget.as_ref().map(|b| b.bodies_loaded),
            "loaded_code_bytes": vm.validation_observer.code_budget.as_ref().map(|b| b.bytes_loaded)})
    }
    fn add(pool: &Mempool, tx: Transaction, concurrency: KeyedConcurrency) -> Result<(), String> {
        let sender = tx.sender(&NativeCrypto).unwrap();
        let mtx = MempoolTransaction::new(tx, sender);
        pool.add_transaction(
            mtx.hash(&NativeCrypto),
            sender,
            mtx,
            None,
            None,
            concurrency,
            None,
        )
        .map_err(|err| format!("{err:?}"))
    }

    #[test]
    fn keyed_verdict_uses_the_real_client_policy() {
        assert_eq!(
            keyed_concurrency_verdict(true, false, false, false),
            KeyedConcurrency::Allowed
        );
        assert_eq!(
            keyed_concurrency_verdict(true, false, true, false),
            KeyedConcurrency::Denied
        );
        assert_eq!(
            keyed_concurrency_verdict(true, false, false, true),
            KeyedConcurrency::Denied
        );
        assert_eq!(
            keyed_concurrency_verdict(true, true, false, false),
            KeyedConcurrency::Denied
        );
        assert_eq!(
            keyed_concurrency_verdict(false, false, false, false),
            KeyedConcurrency::Denied
        );
    }

    #[test]
    fn real_prefix_and_concurrency() {
        let (root, manifest) = manifest();
        let first = std::env::var("POLICY_FIRST")
            .unwrap_or_else(|_| "policy-first.hex".into());
        let second = std::env::var("POLICY_SECOND")
            .unwrap_or_else(|_| "policy-second.hex".into());
        let tx1 = vector(&root, &first);
        let tx2 = vector(&root, &second);
        let mut reports = Vec::new();
        for (filename, tx) in [(&first, &tx1), (&second, &tx2)] {
            for profile2 in [false, true] {
                let mut outcome = prefix(&root, &manifest, tx, profile2, false);
                outcome["file"] = json!(filename);
                assert_eq!(outcome["any_revert"], false, "{outcome}");
                assert!(outcome["violation"].is_null(), "{outcome}");
                assert_eq!(outcome["sender_slots"], json!([]), "{outcome}");
                assert_eq!(outcome["read_legacy_nonce"], false, "{outcome}");
                assert_eq!(outcome["keyed_concurrency"], "Allowed", "{outcome}");
                let Transaction::FrameTransaction(ft) = tx else {
                    unreachable!()
                };
                assert_eq!(outcome["payer"], format!("{:#x}", ft.sender), "{outcome}");
                reports.push(outcome);
            }
        }
        let Transaction::FrameTransaction(ft1) = &tx1 else {
            unreachable!()
        };
        let Transaction::FrameTransaction(ft2) = &tx2 else {
            unreachable!()
        };
        for ft in [ft1, ft2] {
            let candidate = profile2_candidate(ft).unwrap();
            reports.push(json!({"profile2_static_candidate": true, "verify_budget_cost": candidate.verify_budget_cost}));
        }
        assert_eq!(ft1.sender, ft2.sender);
        assert!(
            ft1.nonce_keys
                .iter()
                .all(|key| !ft2.nonce_keys.contains(key)),
            "need disjoint real vectors"
        );
        let pool = Mempool::new(32);
        add(&pool, tx1.clone(), KeyedConcurrency::Allowed).unwrap();
        add(&pool, tx2.clone(), KeyedConcurrency::Allowed).unwrap();
        assert_eq!(pool.content().unwrap().len(), 2);
        reports.push(json!({"real_disjoint_transactions_pending": 2}));

        let blocked = Mempool::new(32);
        add(&blocked, tx1.clone(), KeyedConcurrency::Allowed).unwrap();
        let rejection = add(&blocked, tx2.clone(), KeyedConcurrency::Denied).unwrap_err();
        assert_eq!(blocked.content().unwrap().len(), 1);
        reports.push(json!({"storage_dependent_sibling_rejected": rejection}));

        // Isolate overlap indexing: mutated keys are intentionally not a signed
        // valid transaction, and are tested only at Mempool.add_transaction.
        let mut overlap = tx2.clone();
        if let Transaction::FrameTransaction(ft) = &mut overlap {
            ft.nonce_keys[0] = ft1.nonce_keys[0];
            ft.nonce_keys.sort();
        }
        let overlap_error = add(&pool, overlap, KeyedConcurrency::Allowed).unwrap_err();
        assert_eq!(pool.content().unwrap().len(), 2);
        reports.push(json!({"synthetic_partial_key_overlap_rejected": overlap_error}));

        let ordinary_read = prefix(&root, &manifest, &tx1, false, true);
        assert!(
            !ordinary_read["sender_slots"].as_array().unwrap().is_empty(),
            "{ordinary_read}"
        );
        assert_eq!(ordinary_read["keyed_concurrency"], "Denied");
        assert!(ordinary_read["violation"].is_null());
        reports.push(ordinary_read);
        let profile_read = prefix(&root, &manifest, &tx1, true, true);
        assert!(
            profile_read["violation"]
                .as_str()
                .unwrap()
                .contains("StorageReadOutsideSurface"),
            "{profile_read}"
        );
        reports.push(profile_read);
        let fixture_files = manifest["setup"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["raw"].as_str().unwrap().to_string())
            .chain([first.clone(), second.clone()]);
        let fixture_hashes: serde_json::Map<_, _> = fixture_files
            .map(|filename| {
                let digest = format!("{:#x}", keccak(read_hex(&root.join(&filename))));
                (filename, json!(digest))
            })
            .collect();
        let source_hashes: serde_json::Map<_, _> = [
            "crates/blockchain/mempool.rs",
            "crates/blockchain/focil_profile2.rs",
            "crates/vm/levm/src/vm.rs",
            "crates/vm/levm/src/validation_observer.rs",
        ]
        .into_iter()
        .map(|filename| {
            let digest = format!(
                "{:#x}",
                keccak(fs::read(Path::new(env!("ETHREX_SOURCE")).join(filename)).unwrap())
            );
            (filename.to_string(), json!(digest))
        })
        .collect();
        let report = json!({"first": first, "second": second,
            "ethrex_revision": "247e2dd2c4d4c526dcc64ac1c025bd2319e7a10e", "client_source_keccak256": source_hashes,
            "fixture_keccak256": fixture_hashes,
            "scope": "Real LEVM prefix execution, Profile2 static candidacy/storage/trace/code-budget checks, direct client mempool insertion. Not full blockchain admission, inclusion-list omission processing, block import or networking. Default 100k public-mempool validation gas gate is not relaxed by this candidate; these pool fixtures already exceed it.",
            "results": reports});
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        if let Ok(output) = std::env::var("POLICY_REPORT") {
            fs::write(
                output,
                serde_json::to_string_pretty(&report).unwrap() + "\n",
            )
            .unwrap();
        }
    }
}
