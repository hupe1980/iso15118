//! Seals a secp521r1 contract key for a vehicle's TPM 2.0 storage key and
//! writes `TPM2_Import`'s three inputs — the crate's half of
//! `scripts/verify-tpm-import.sh`.
//!
//! ```text
//! cargo run --example tpm_seal --features pnc-rustcrypto -- <storage X‖Y hex> <out dir> [policy digest hex]
//! ```
//!
//! Writes `object.pub` (`TPM2B_PUBLIC`), `duplicate.priv` (`TPM2B_PRIVATE`),
//! `seed.dat` (`TPM2B_ENCRYPTED_SECRET`) and `contract.pub` (the contract key's
//! uncompressed point). The keys are fixed test keys.

use std::path::PathBuf;

use iso15118::pnc::envelope::tpm::{self, TpmInfo};
use iso15118::pnc::rustcrypto::{AgreementKey, Backend, Sha2};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (storage, out) = match args.as_slice() {
        [storage, out, ..] => (hex(storage), PathBuf::from(out)),
        _ => return Err("usage: tpm_seal <storage X‖Y hex> <out dir> [policy hex]".into()),
    };
    let policy_digest = args
        .get(2)
        .map(|p| <[u8; 64]>::try_from(hex(p)))
        .transpose()
        .map_err(|_| "the policy digest is not 64 bytes")?;
    let info = TpmInfo {
        storage_key: storage.try_into().map_err(|_| "the storage key is not 132 bytes")?,
        policy_digest,
    };

    // Fixed test scalars below the P-521 group order (top byte 0x00).
    let mut contract_scalar = [0x11; 66];
    contract_scalar[0] = 0;
    let contract = AgreementKey::p521(&contract_scalar)?.public_key();
    let mut ephemeral_scalar = [0x22; 66];
    ephemeral_scalar[0] = 0;
    let ephemeral = AgreementKey::p521(&ephemeral_scalar)?;
    let sealed = tpm::seal(
        &contract_scalar,
        &contract,
        &info,
        &ephemeral,
        &ephemeral.public_key(),
        &Sha2,
        &Backend,
        &Backend,
    )?;
    assert!(sealed.encrypted_private_key.len() <= tpm::MAX_ENCRYPTED_PRIVATE_KEY_LEN);

    // The vehicle's half: what it received, turned into TPM2_Import's inputs.
    let inputs = tpm::import_inputs(
        &contract,
        info.policy_digest.as_ref(),
        &sealed.encrypted_private_key,
        &sealed.dh_public_key,
    )?;
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("object.pub"), &inputs.public)?;
    std::fs::write(out.join("duplicate.priv"), &inputs.duplicate)?;
    std::fs::write(out.join("seed.dat"), &inputs.in_sym_seed)?;
    std::fs::write(out.join("contract.pub"), &contract)?;
    println!("sealed {} bytes for the TPM", sealed.encrypted_private_key.len());
    Ok(())
}
