extern crate failure;

#[macro_use]
extern crate log;

extern crate ff;
extern crate pairing;
extern crate rusqlite;
extern crate zcash_client_backend;
extern crate zcash_primitives;
extern crate zip32;

use failure::Error;
use ff::{PrimeField, PrimeFieldRepr};
use rusqlite::{types::ToSql, Connection, NO_PARAMS};
use zcash_client_backend::{
    address::encode_payment_address, constants::HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST,
    welding_rig::scan_block_from_bytes,
};
use zcash_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use zip32::{ChildIndex, ExtendedFullViewingKey, ExtendedSpendingKey};

fn extfvk_from_seed(seed: &[u8]) -> ExtendedFullViewingKey {
    let master = ExtendedSpendingKey::master(seed);
    let extsk = ExtendedSpendingKey::from_path(
        &master,
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(1),
            ChildIndex::Hardened(0),
        ],
    );
    ExtendedFullViewingKey::from(&extsk)
}

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST, &addr)
}

fn init_data_database(db_data: &str) -> rusqlite::Result<()> {
    let data = Connection::open(db_data)?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            time INTEGER,
            sapling_tree BLOB
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            id_tx INTEGER PRIMARY KEY,
            txid BLOB NOT NULL UNIQUE,
            block INTEGER NOT NULL,
            FOREIGN KEY (block) REFERENCES blocks(height)
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS received_notes (
            id_note INTEGER PRIMARY KEY,
            tx INTEGER NOT NULL,
            output_index INTEGER NOT NULL,
            account INTEGER NOT NULL,
            diversifier BLOB NOT NULL,
            value INTEGER NOT NULL,
            rcm BLOB NOT NULL,
            memo BLOB,
            spent INTEGER,
            FOREIGN KEY (tx) REFERENCES transactions(id_tx),
            FOREIGN KEY (spent) REFERENCES transactions(id_tx),
            CONSTRAINT tx_output UNIQUE (tx, output_index)
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS sapling_witnesses (
            id_witness INTEGER PRIMARY KEY,
            note INTEGER NOT NULL,
            block INTEGER NOT NULL,
            witness BLOB NOT NULL,
            FOREIGN KEY (note) REFERENCES received_notes(id_note),
            FOREIGN KEY (block) REFERENCES blocks(height),
            CONSTRAINT witness_height UNIQUE (note, block)
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

struct CompactBlockRow {
    height: i32,
    data: Vec<u8>,
}

#[derive(Clone)]
struct WitnessRow {
    id_note: i64,
    witness: IncrementalWitness,
}

/// Scans new blocks added to the cache for any transactions received by the given
/// ExtendedFullViewingKeys.
///
/// Assumes that the caller is handling rollbacks.
fn scan_cached_blocks(
    db_cache: &str,
    db_data: &str,
    extfvks: &[ExtendedFullViewingKey],
    birthday: i32,
) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously
    let mut last_height =
        data.query_row(
            "SELECT MAX(height) FROM blocks",
            NO_PARAMS,
            |row| match row.get_checked(0) {
                Ok(h) => h,
                Err(_) => birthday,
            },
        )?;

    // Prepare necessary SQL statements
    let mut stmt_blocks = cache
        .prepare("SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC")?;
    let mut stmt_fetch_tree = data.prepare("SELECT sapling_tree FROM blocks WHERE height = ?")?;
    let mut stmt_fetch_witnesses =
        data.prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let mut stmt_insert_block = data.prepare(
        "INSERT INTO blocks (height, sapling_tree)
        VALUES (?, ?)",
    )?;
    let mut stmt_insert_tx = data.prepare(
        "INSERT INTO transactions (txid, block)
        VALUES (?, ?)",
    )?;
    let mut stmt_insert_note = data.prepare(
        "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm)
        VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    let mut stmt_insert_witness = data.prepare(
        "INSERT INTO sapling_witnesses (note, block, witness)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_prune_witnesses = data.prepare("DELETE FROM sapling_witnesses WHERE block < ?")?;

    // Fetch the CompactBlocks we need to scan
    let rows = stmt_blocks.query_map(&[last_height], |row| CompactBlockRow {
        height: row.get(0),
        data: row.get(1),
    })?;

    // Get the most recent CommitmentTree
    let mut tree = match stmt_fetch_tree.query_row(&[last_height], |row| match row.get_checked(0) {
        Ok(data) => {
            let data: Vec<_> = data;
            CommitmentTree::read(&data[..]).unwrap()
        }
        Err(_) => CommitmentTree::new(),
    }) {
        Ok(tree) => tree,
        Err(_) => CommitmentTree::new(),
    };

    // Get most recent incremental witnesses for the notes we are tracking
    let witnesses = stmt_fetch_witnesses.query_map(&[last_height], |row| {
        let data: Vec<_> = row.get(1);
        WitnessRow {
            id_note: row.get(0),
            witness: IncrementalWitness::read(&data[..]).unwrap(),
        }
    })?;
    let mut witnesses: Vec<_> = witnesses.into_iter().collect::<Result<_, _>>()?;

    for row in rows {
        let row = row?;

        // Start an SQL transaction for this block.
        data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

        // Scanned blocks MUST be height-seqential.
        if row.height != (last_height + 1) {
            error!(
                "Expected height of next CompactBlock to be {}, but was {}",
                last_height + 1,
                row.height
            );
            // Nothing more we can do
            break;
        }
        last_height = row.height;

        let txs = {
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.witness).collect();
            scan_block_from_bytes(&row.data, &extfvks, &mut tree, &mut witness_refs[..])
        };

        // Insert the block into the database.
        let mut encoded_tree = Vec::new();
        tree.write(&mut encoded_tree).unwrap();
        stmt_insert_block.execute(&[row.height.to_sql()?, encoded_tree.to_sql()?])?;

        for (tx, new_witnesses) in txs {
            // Insert our transaction into the database.
            stmt_insert_tx.execute(&[tx.txid.0.to_vec().to_sql()?, row.height.to_sql()?])?;
            let tx_row = data.last_insert_rowid();

            for (output, witness) in tx
                .shielded_outputs
                .into_iter()
                .zip(new_witnesses.into_iter())
            {
                let mut rcm = [0; 32];
                output.note.r.into_repr().write_le(&mut rcm[..])?;

                // Insert received note into the database.
                // Assumptions:
                // - A transaction will not contain more than 2^63 shielded outputs.
                // - A note value will never exceed 2^63 zatoshis.
                stmt_insert_note.execute(&[
                    tx_row.to_sql()?,
                    (output.index as i64).to_sql()?,
                    (output.account as i64).to_sql()?,
                    output.to.diversifier.0.to_sql()?,
                    (output.note.value as i64).to_sql()?,
                    rcm.to_sql()?,
                ])?;
                let note_row = data.last_insert_rowid();

                // Save witness for note.
                witnesses.push(WitnessRow {
                    id_note: note_row,
                    witness,
                });
            }
        }

        // Insert current witnesses into the database.
        let mut encoded = Vec::new();
        for witness_row in witnesses.iter() {
            encoded.clear();
            witness_row.witness.write(&mut encoded).unwrap();
            stmt_insert_witness.execute(&[
                witness_row.id_note.to_sql()?,
                last_height.to_sql()?,
                encoded.to_sql()?,
            ])?;
        }

        // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
        stmt_prune_witnesses.execute(&[last_height - 100])?;

        // Commit the SQL transaction, writing this block's data atomically.
        data.execute("COMMIT", NO_PARAMS)?;
    }

    Ok(())
}

/// JNI interface
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate android_logger;
    extern crate jni;
    extern crate log_panics;

    use log::Level;

    use self::android_logger::Filter;
    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jbyteArray, jint, jstring};
    use self::jni::JNIEnv;

    use super::{address_from_extfvk, extfvk_from_seed, scan_cached_blocks};

    #[no_mangle]
    pub unsafe extern "C" fn Java_cash_z_wallet_sdk_jni_JniConverter_initLogs(
        _env: JNIEnv,
        _: JClass,
    ) {
        android_logger::init_once(
            Filter::default().with_min_level(Level::Trace),
            Some("cash.z.rust.logs"),
        );

        log_panics::init();

        debug!("logs have been initialized successfully");
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_cash_z_wallet_sdk_jni_JniConverter_getAddress(
        env: JNIEnv,
        _: JClass,
        seed: jbyteArray,
    ) -> jstring {
        let seed = env.convert_byte_array(seed).unwrap();

        let addr = address_from_extfvk(&extfvk_from_seed(&seed));

        let output = env.new_string(addr).expect("Couldn't create Java string!");
        output.into_inner()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_cash_z_wallet_sdk_jni_JniConverter_scanBlocks(
        env: JNIEnv,
        _: JClass,
        db_cache: JString,
        db_data: JString,
        seed: jbyteArray,
        birthday: jint,
    ) {
        let db_cache: String = env
            .get_string(db_cache)
            .expect("Couldn't get Java string!")
            .into();
        let db_data: String = env
            .get_string(db_data)
            .expect("Couldn't get Java string!")
            .into();
        let seed = env.convert_byte_array(seed).unwrap();

        if let Err(e) =
            scan_cached_blocks(&db_cache, &db_data, &[extfvk_from_seed(&seed)], birthday)
        {
            error!("Error while scanning blocks: {}", e);
        }
    }
}
