/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

use hpke_rs::{
    hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    Hpke, HpkePrivateKey, HpkePublicKey, Mode,
};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto as Provider;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use tls_codec::{Deserialize, Serialize};

const ABI_VERSION: u32 = 0x0001_0006;
const STATUS_OK: u32 = 0;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_INVALID_STATE: u32 = 2;
const STATUS_CODEC_ERROR: u32 = 3;
const STATUS_CRYPTO_ERROR: u32 = 4;
const STATUS_UNSUPPORTED: u32 = 5;
const STATUS_PANIC: u32 = 255;

const CONTENT_NONE: u32 = 0;
const CONTENT_APPLICATION: u32 = 1;
const CONTENT_PROPOSAL: u32 = 2;
const CONTENT_COMMIT: u32 = 3;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const GROUP_ID_SIZE: usize = 32;
const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
const MAX_IDENTITY_SIZE: usize = 16 * 1024;
const MAX_STATE_SIZE: usize = 64 * 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 65_536;
const MAX_STATE_KEY_SIZE: usize = 1024 * 1024;
const MAX_STATE_VALUE_SIZE: usize = 16 * 1024 * 1024;
const MAX_KEY_PACKAGE_SIZE: usize = 1024 * 1024;
const MAX_KEY_PACKAGE_LIST_SIZE: usize = 16 * 1024 * 1024;
const KEY_PACKAGE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 28 * 3;
const MAX_WELCOME_SIZE: usize = 16 * 1024 * 1024;
const MAX_MLS_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const MAX_APPLICATION_SIZE: usize = 1024 * 1024;
const MAX_AUTHENTICATED_DATA_SIZE: usize = 1024 * 1024;
const MAX_ROSTER_SIZE: usize = 16 * 1024 * 1024;
const MAX_ROSTER_MEMBERS: usize = 4096;
const MAX_PAST_EPOCHS: usize = 8;
const HPKE_KEY_SIZE: usize = 32;
const HPKE_TAG_SIZE: usize = 16;
const MAX_HPKE_INFO_SIZE: usize = 1024 * 1024;
const MAX_HPKE_AAD_SIZE: usize = 1024 * 1024;
const MAX_HPKE_PLAINTEXT_SIZE: usize = 16 * 1024 * 1024;
const NON_MEMBER_SENDER: u32 = u32::MAX;
const STATE_MAGIC: &[u8; 8] = b"TDE2OMLS";
const ROSTER_MAGIC: &[u8; 8] = b"TDE2EROS";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    KeyPackage = 1,
    Group = 2,
}

impl TryFrom<u8> for Stage {
    type Error = BridgeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::KeyPackage),
            2 => Ok(Self::Group),
            _ => Err(BridgeError::InvalidState),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BridgeError {
    InvalidArgument,
    InvalidState,
    Codec,
    Crypto,
    Unsupported,
}

impl BridgeError {
    fn status(self) -> u32 {
        match self {
            Self::InvalidArgument => STATUS_INVALID_ARGUMENT,
            Self::InvalidState => STATUS_INVALID_STATE,
            Self::Codec => STATUS_CODEC_ERROR,
            Self::Crypto => STATUS_CRYPTO_ERROR,
            Self::Unsupported => STATUS_UNSUPPORTED,
        }
    }
}

type BridgeResult<T> = Result<T, BridgeError>;

struct Snapshot {
    stage: Stage,
    group_id: Vec<u8>,
    identity: Vec<u8>,
    signer_public_key: Vec<u8>,
    values: BTreeMap<Vec<u8>, Vec<u8>>,
}

struct Restored {
    provider: Provider,
    stage: Stage,
    group_id: Vec<u8>,
    identity: Vec<u8>,
    signer_public_key: Vec<u8>,
}

struct StateOutput {
    state: Vec<u8>,
    roster: Vec<u8>,
    epoch: u64,
}

struct KeyPackageOutput {
    state: Vec<u8>,
    key_package: Vec<u8>,
}

struct CommitOutput {
    state: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
    roster: Vec<u8>,
    epoch: u64,
}

struct SealOutput {
    state: Vec<u8>,
    message: Vec<u8>,
    epoch: u64,
}

struct ProcessOutput {
    state: Vec<u8>,
    plaintext: Vec<u8>,
    authenticated_data: Vec<u8>,
    sender_credential: Vec<u8>,
    roster: Vec<u8>,
    kind: u32,
    sender_index: u32,
    epoch: u64,
}

struct HpkeSealOutput {
    encapsulated_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, size: usize) -> BridgeResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(BridgeError::InvalidState)?;
        if end > self.bytes.len() {
            return Err(BridgeError::InvalidState);
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn read_u8(&mut self) -> BridgeResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> BridgeResult<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| BridgeError::InvalidState)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> BridgeResult<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| BridgeError::InvalidState)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_vec(&mut self, size: usize, maximum: usize) -> BridgeResult<Vec<u8>> {
        if size > maximum {
            return Err(BridgeError::InvalidState);
        }
        Ok(self.take(size)?.to_vec())
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn append_u16(result: &mut Vec<u8>, value: usize) -> BridgeResult<()> {
    let value = u16::try_from(value).map_err(|_| BridgeError::InvalidState)?;
    result.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn append_u32(result: &mut Vec<u8>, value: usize) -> BridgeResult<()> {
    let value = u32::try_from(value).map_err(|_| BridgeError::InvalidState)?;
    result.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn validate_metadata(
    group_id: &[u8],
    identity: &[u8],
    signer_public_key: &[u8],
) -> BridgeResult<()> {
    if group_id.len() != GROUP_ID_SIZE
        || identity.is_empty()
        || identity.len() > MAX_IDENTITY_SIZE
        || signer_public_key.len() != SIGNATURE_PUBLIC_KEY_SIZE
    {
        return Err(BridgeError::InvalidState);
    }
    Ok(())
}

fn decode_snapshot(bytes: &[u8]) -> BridgeResult<Snapshot> {
    if bytes.len() > MAX_STATE_SIZE {
        return Err(BridgeError::InvalidState);
    }
    let mut reader = Reader::new(bytes);
    if reader.take(STATE_MAGIC.len())? != STATE_MAGIC || reader.read_u16()? != 1 {
        return Err(BridgeError::InvalidState);
    }
    let stage = Stage::try_from(reader.read_u8()?)?;
    if reader.read_u8()? != 0 {
        return Err(BridgeError::InvalidState);
    }
    let group_id_size = usize::from(reader.read_u16()?);
    let group_id = reader.read_vec(group_id_size, GROUP_ID_SIZE)?;
    let identity_size =
        usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidState)?;
    let identity = reader.read_vec(identity_size, MAX_IDENTITY_SIZE)?;
    let signer_size = usize::from(reader.read_u16()?);
    let signer_public_key = reader.read_vec(signer_size, SIGNATURE_PUBLIC_KEY_SIZE)?;
    validate_metadata(&group_id, &identity, &signer_public_key)?;
    let count = usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidState)?;
    if count == 0 || count > MAX_STATE_ENTRIES {
        return Err(BridgeError::InvalidState);
    }
    let mut values = BTreeMap::new();
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..count {
        let key_size =
            usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidState)?;
        let value_size =
            usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidState)?;
        if key_size == 0 {
            return Err(BridgeError::InvalidState);
        }
        let key = reader.read_vec(key_size, MAX_STATE_KEY_SIZE)?;
        let value = reader.read_vec(value_size, MAX_STATE_VALUE_SIZE)?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(BridgeError::InvalidState);
        }
        previous_key = Some(key.clone());
        values.insert(key, value);
    }
    if !reader.finished() {
        return Err(BridgeError::InvalidState);
    }
    Ok(Snapshot {
        stage,
        group_id,
        identity,
        signer_public_key,
        values,
    })
}

fn encode_snapshot(
    provider: &Provider,
    stage: Stage,
    group_id: &[u8],
    identity: &[u8],
    signer_public_key: &[u8],
) -> BridgeResult<Vec<u8>> {
    validate_metadata(group_id, identity, signer_public_key)?;
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| BridgeError::InvalidState)?;
    if values.is_empty() || values.len() > MAX_STATE_ENTRIES {
        return Err(BridgeError::InvalidState);
    }
    let mut ordered = values.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let mut result = Vec::new();
    result.extend_from_slice(STATE_MAGIC);
    result.extend_from_slice(&1_u16.to_be_bytes());
    result.push(stage as u8);
    result.push(0);
    append_u16(&mut result, group_id.len())?;
    result.extend_from_slice(group_id);
    append_u32(&mut result, identity.len())?;
    result.extend_from_slice(identity);
    append_u16(&mut result, signer_public_key.len())?;
    result.extend_from_slice(signer_public_key);
    append_u32(&mut result, ordered.len())?;
    for (key, value) in ordered {
        if key.is_empty() || key.len() > MAX_STATE_KEY_SIZE || value.len() > MAX_STATE_VALUE_SIZE {
            return Err(BridgeError::InvalidState);
        }
        append_u32(&mut result, key.len())?;
        append_u32(&mut result, value.len())?;
        result.extend_from_slice(key);
        result.extend_from_slice(value);
        if result.len() > MAX_STATE_SIZE {
            return Err(BridgeError::InvalidState);
        }
    }
    Ok(result)
}

fn restore(bytes: &[u8], expected_stage: Stage) -> BridgeResult<Restored> {
    let snapshot = decode_snapshot(bytes)?;
    if snapshot.stage != expected_stage {
        return Err(BridgeError::InvalidState);
    }
    let provider = Provider::default();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|_| BridgeError::InvalidState)?;
        *values = snapshot.values.into_iter().collect::<HashMap<_, _>>();
    }
    Ok(Restored {
        provider,
        stage: snapshot.stage,
        group_id: snapshot.group_id,
        identity: snapshot.identity,
        signer_public_key: snapshot.signer_public_key,
    })
}

fn create_identity(
    provider: &Provider,
    identity: &[u8],
) -> BridgeResult<(CredentialWithKey, SignatureKeyPair)> {
    if identity.is_empty() || identity.len() > MAX_IDENTITY_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let signer =
        SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|_| BridgeError::Crypto)?;
    signer
        .store(provider.storage())
        .map_err(|_| BridgeError::InvalidState)?;
    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    Ok((credential_with_key, signer))
}

fn load_signer(restored: &Restored) -> BridgeResult<SignatureKeyPair> {
    SignatureKeyPair::read(
        restored.provider.storage(),
        &restored.signer_public_key,
        SignatureScheme::ED25519,
    )
    .ok_or(BridgeError::InvalidState)
}

fn load_group(restored: &Restored) -> BridgeResult<MlsGroup> {
    if restored.stage != Stage::Group {
        return Err(BridgeError::InvalidState);
    }
    let group_id = GroupId::from_slice(&restored.group_id);
    let group = MlsGroup::load(restored.provider.storage(), &group_id)
        .map_err(|_| BridgeError::InvalidState)?
        .ok_or(BridgeError::InvalidState)?;
    if group.group_id().as_slice() != restored.group_id || group.ciphersuite() != CIPHERSUITE {
        return Err(BridgeError::InvalidState);
    }
    let own_leaf = group.own_leaf_node().ok_or(BridgeError::InvalidState)?;
    if own_leaf.credential().credential_type() != CredentialType::Basic
        || own_leaf.credential().serialized_content() != restored.identity
        || own_leaf.signature_key().as_slice() != restored.signer_public_key
    {
        return Err(BridgeError::InvalidState);
    }
    Ok(group)
}

fn encode_roster(group: &MlsGroup) -> BridgeResult<Vec<u8>> {
    let mut members = group.members().collect::<Vec<_>>();
    members.sort_by_key(|member| member.index.u32());
    let mut result = Vec::new();
    result.extend_from_slice(ROSTER_MAGIC);
    result.extend_from_slice(&1_u16.to_be_bytes());
    result.extend_from_slice(group.group_id().as_slice());
    result.extend_from_slice(&group.epoch().as_u64().to_be_bytes());
    append_u32(&mut result, members.len())?;
    for member in members {
        let identity = member.credential.serialized_content();
        if member.credential.credential_type() != CredentialType::Basic
            || identity.is_empty()
            || identity.len() > MAX_IDENTITY_SIZE
            || member.signature_key.len() != SIGNATURE_PUBLIC_KEY_SIZE
            || member.encryption_key.is_empty()
            || member.encryption_key.len() > 1024
        {
            return Err(BridgeError::Unsupported);
        }
        result.extend_from_slice(&member.index.u32().to_be_bytes());
        append_u32(&mut result, identity.len())?;
        result.extend_from_slice(identity);
        append_u16(&mut result, member.signature_key.len())?;
        result.extend_from_slice(&member.signature_key);
        append_u16(&mut result, member.encryption_key.len())?;
        result.extend_from_slice(&member.encryption_key);
        if result.len() > MAX_ROSTER_SIZE {
            return Err(BridgeError::InvalidState);
        }
    }
    Ok(result)
}

fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build()
}

fn create_group_impl(identity: &[u8], group_id: &[u8]) -> BridgeResult<StateOutput> {
    if group_id.len() != GROUP_ID_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let provider = Provider::default();
    let (credential_with_key, signer) = create_identity(&provider, identity)?;
    let group = MlsGroup::builder()
        .ciphersuite(CIPHERSUITE)
        .with_group_id(GroupId::from_slice(group_id))
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build(&provider, &signer, credential_with_key)
        .map_err(|_| BridgeError::Crypto)?;
    let state = encode_snapshot(&provider, Stage::Group, group_id, identity, signer.public())?;
    Ok(StateOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
    })
}

fn inspect_group_impl(state: &[u8]) -> BridgeResult<StateOutput> {
    let restored = restore(state, Stage::Group)?;
    let group = load_group(&restored)?;
    Ok(StateOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state: state.to_vec(),
    })
}

fn create_key_package_impl(
    identity: &[u8],
    expected_group_id: &[u8],
) -> BridgeResult<KeyPackageOutput> {
    if expected_group_id.len() != GROUP_ID_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let provider = Provider::default();
    let (credential_with_key, signer) = create_identity(&provider, identity)?;
    let key_package = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECONDS))
        .build(CIPHERSUITE, &provider, &signer, credential_with_key)
        .map_err(|_| BridgeError::Crypto)?;
    let key_package = key_package
        .key_package()
        .tls_serialize_detached()
        .map_err(|_| BridgeError::Codec)?;
    if key_package.len() > MAX_KEY_PACKAGE_SIZE {
        return Err(BridgeError::InvalidState);
    }
    let state = encode_snapshot(
        &provider,
        Stage::KeyPackage,
        expected_group_id,
        identity,
        signer.public(),
    )?;
    Ok(KeyPackageOutput { state, key_package })
}

fn inspect_key_package_state_impl(state: &[u8]) -> BridgeResult<()> {
    let restored = restore(state, Stage::KeyPackage)?;
    load_signer(&restored)?;
    Ok(())
}

fn parse_key_package(provider: &Provider, bytes: &[u8]) -> BridgeResult<KeyPackage> {
    if bytes.is_empty() || bytes.len() > MAX_KEY_PACKAGE_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let key_package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|_| BridgeError::Codec)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| BridgeError::Crypto)?;
    let credential = key_package.leaf_node().credential();
    if key_package.ciphersuite() != CIPHERSUITE
        || credential.credential_type() != CredentialType::Basic
        || credential.serialized_content().is_empty()
        || credential.serialized_content().len() > MAX_IDENTITY_SIZE
        || key_package.leaf_node().signature_key().as_slice().len() != SIGNATURE_PUBLIC_KEY_SIZE
    {
        return Err(BridgeError::Unsupported);
    }
    Ok(key_package)
}

fn validate_aad(authenticated_data: &[u8]) -> BridgeResult<()> {
    if authenticated_data.is_empty() || authenticated_data.len() > MAX_AUTHENTICATED_DATA_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    Ok(())
}

fn hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    )
}

fn hpke_seal_impl(
    recipient_public_key: &[u8],
    info: &[u8],
    authenticated_data: &[u8],
    plaintext: &[u8],
) -> BridgeResult<HpkeSealOutput> {
    if recipient_public_key.len() != HPKE_KEY_SIZE
        || info.is_empty()
        || info.len() > MAX_HPKE_INFO_SIZE
        || authenticated_data.is_empty()
        || authenticated_data.len() > MAX_HPKE_AAD_SIZE
        || plaintext.is_empty()
        || plaintext.len() > MAX_HPKE_PLAINTEXT_SIZE
    {
        return Err(BridgeError::InvalidArgument);
    }
    let public_key = HpkePublicKey::from(recipient_public_key);
    let (encapsulated_key, ciphertext) = hpke()
        .seal(
            &public_key,
            info,
            authenticated_data,
            plaintext,
            None,
            None,
            None,
        )
        .map_err(|_| BridgeError::Crypto)?;
    if encapsulated_key.len() != HPKE_KEY_SIZE
        || ciphertext.len() != plaintext.len() + HPKE_TAG_SIZE
    {
        return Err(BridgeError::InvalidState);
    }
    Ok(HpkeSealOutput {
        encapsulated_key,
        ciphertext,
    })
}

fn hpke_open_impl(
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    authenticated_data: &[u8],
    ciphertext: &[u8],
) -> BridgeResult<Vec<u8>> {
    if recipient_private_key.len() != HPKE_KEY_SIZE
        || encapsulated_key.len() != HPKE_KEY_SIZE
        || info.is_empty()
        || info.len() > MAX_HPKE_INFO_SIZE
        || authenticated_data.is_empty()
        || authenticated_data.len() > MAX_HPKE_AAD_SIZE
        || ciphertext.len() <= HPKE_TAG_SIZE
        || ciphertext.len() > MAX_HPKE_PLAINTEXT_SIZE + HPKE_TAG_SIZE
    {
        return Err(BridgeError::InvalidArgument);
    }
    let private_key = HpkePrivateKey::from(recipient_private_key);
    let plaintext = hpke()
        .open(
            encapsulated_key,
            &private_key,
            info,
            authenticated_data,
            ciphertext,
            None,
            None,
            None,
        )
        .map_err(|_| BridgeError::Crypto)?;
    if plaintext.is_empty() || plaintext.len() > MAX_HPKE_PLAINTEXT_SIZE {
        return Err(BridgeError::InvalidState);
    }
    Ok(plaintext)
}

fn add_member_impl(
    state: &[u8],
    key_package: &[u8],
    authenticated_data: &[u8],
) -> BridgeResult<CommitOutput> {
    validate_aad(authenticated_data)?;
    let restored = restore(state, Stage::Group)?;
    let signer = load_signer(&restored)?;
    let mut group = load_group(&restored)?;
    let key_package = parse_key_package(&restored.provider, key_package)?;
    group.set_aad(authenticated_data.to_vec());
    let (commit, welcome, _) = group
        .add_members(&restored.provider, &signer, &[key_package])
        .map_err(|_| BridgeError::Crypto)?;
    let commit = commit.to_bytes().map_err(|_| BridgeError::Codec)?;
    let welcome = welcome.to_bytes().map_err(|_| BridgeError::Codec)?;
    group
        .merge_pending_commit(&restored.provider)
        .map_err(|_| BridgeError::InvalidState)?;
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(CommitOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
        commit,
        welcome,
    })
}

fn update_group_impl(state: &[u8], authenticated_data: &[u8]) -> BridgeResult<CommitOutput> {
    validate_aad(authenticated_data)?;
    let restored = restore(state, Stage::Group)?;
    let signer = load_signer(&restored)?;
    let mut group = load_group(&restored)?;
    group.set_aad(authenticated_data.to_vec());
    let (commit, welcome, _) = group
        .self_update(&restored.provider, &signer, LeafNodeParameters::default())
        .map_err(|_| BridgeError::Crypto)?
        .into_contents();
    if welcome.is_some() {
        return Err(BridgeError::InvalidState);
    }
    let commit = commit.to_bytes().map_err(|_| BridgeError::Codec)?;
    group
        .merge_pending_commit(&restored.provider)
        .map_err(|_| BridgeError::InvalidState)?;
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(CommitOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
        commit,
        welcome: Vec::new(),
    })
}

fn remove_member_impl(
    state: &[u8],
    leaf_indices: &[u32],
    authenticated_data: &[u8],
) -> BridgeResult<CommitOutput> {
    validate_aad(authenticated_data)?;
    if leaf_indices.is_empty() || leaf_indices.len() > MAX_ROSTER_MEMBERS {
        return Err(BridgeError::InvalidArgument);
    }
    let restored = restore(state, Stage::Group)?;
    let signer = load_signer(&restored)?;
    let mut group = load_group(&restored)?;
    let mut unique = BTreeSet::new();
    let mut leaves = Vec::with_capacity(leaf_indices.len());
    for index in leaf_indices {
        let leaf = LeafNodeIndex::new(*index);
        if leaf == group.own_leaf_index() || group.member(leaf).is_none() || !unique.insert(*index)
        {
            return Err(BridgeError::InvalidArgument);
        }
        leaves.push(leaf);
    }
    group.set_aad(authenticated_data.to_vec());
    let (commit, welcome, _) = group
        .remove_members(&restored.provider, &signer, &leaves)
        .map_err(|_| BridgeError::Crypto)?;
    if welcome.is_some() {
        return Err(BridgeError::InvalidState);
    }
    let commit = commit.to_bytes().map_err(|_| BridgeError::Codec)?;
    group
        .merge_pending_commit(&restored.provider)
        .map_err(|_| BridgeError::InvalidState)?;
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(CommitOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
        commit,
        welcome: Vec::new(),
    })
}

fn recover_fork_impl(
    state: &[u8],
    own_partition: &[u32],
    encoded_key_packages: &[u8],
    authenticated_data: &[u8],
) -> BridgeResult<CommitOutput> {
    validate_aad(authenticated_data)?;
    if own_partition.is_empty() || own_partition.len() > MAX_ROSTER_MEMBERS {
        return Err(BridgeError::InvalidArgument);
    }
    let restored = restore(state, Stage::Group)?;
    let signer = load_signer(&restored)?;
    let mut group = load_group(&restored)?;
    let mut unique = BTreeSet::new();
    let mut own_leaves = Vec::with_capacity(own_partition.len());
    for index in own_partition {
        let leaf = LeafNodeIndex::new(*index);
        if group.member(leaf).is_none() || !unique.insert(*index) {
            return Err(BridgeError::InvalidArgument);
        }
        own_leaves.push(leaf);
    }
    if !own_leaves.contains(&group.own_leaf_index()) {
        return Err(BridgeError::InvalidArgument);
    }
    let mut reader = Reader::new(encoded_key_packages);
    let count = usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidArgument)?;
    if count == 0 || count > MAX_ROSTER_MEMBERS {
        return Err(BridgeError::InvalidArgument);
    }
    let mut packages = Vec::with_capacity(count);
    for _ in 0..count {
        let size = usize::try_from(reader.read_u32()?).map_err(|_| BridgeError::InvalidArgument)?;
        let bytes = reader.read_vec(size, MAX_KEY_PACKAGE_SIZE)?;
        packages.push(parse_key_package(&restored.provider, &bytes)?);
    }
    if !reader.finished() {
        return Err(BridgeError::InvalidArgument);
    }
    group.set_aad(authenticated_data.to_vec());
    let builder = group
        .recover_fork_by_readding(&own_leaves)
        .map_err(|_| BridgeError::InvalidArgument)?;
    let complement = builder.complement_partition();
    if complement.len() != packages.len()
        || complement
            .iter()
            .zip(packages.iter())
            .any(|(member, package)| {
                member.credential.credential_type() != CredentialType::Basic
                    || package.leaf_node().credential().credential_type() != CredentialType::Basic
                    || member.credential.serialized_content()
                        != package.leaf_node().credential().serialized_content()
            })
    {
        return Err(BridgeError::InvalidArgument);
    }
    let messages = builder
        .provide_key_packages(packages)
        .load_psks(restored.provider.storage())
        .map_err(|_| BridgeError::Crypto)?
        .build(
            restored.provider.rand(),
            restored.provider.crypto(),
            &signer,
            |_| true,
        )
        .map_err(|_| BridgeError::Crypto)?
        .stage_commit(&restored.provider)
        .map_err(|_| BridgeError::Crypto)?;
    let (commit, welcome, _) = messages.into_contents();
    let welcome = welcome.ok_or(BridgeError::InvalidState)?;
    let commit = commit.to_bytes().map_err(|_| BridgeError::Codec)?;
    let welcome = MlsMessageOut::from_welcome(welcome, ProtocolVersion::Mls10)
        .to_bytes()
        .map_err(|_| BridgeError::Codec)?;
    group
        .merge_pending_commit(&restored.provider)
        .map_err(|_| BridgeError::InvalidState)?;
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(CommitOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
        commit,
        welcome,
    })
}

fn join_impl(state: &[u8], welcome: &[u8]) -> BridgeResult<StateOutput> {
    if welcome.is_empty() || welcome.len() > MAX_WELCOME_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let restored = restore(state, Stage::KeyPackage)?;
    let welcome = match MlsMessageIn::tls_deserialize_exact(welcome)
        .map_err(|_| BridgeError::Codec)?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(BridgeError::Codec),
    };
    let staged =
        StagedWelcome::new_from_welcome(&restored.provider, &group_join_config(), welcome, None)
            .map_err(|_| BridgeError::Crypto)?;
    if staged.group_context().group_id().as_slice() != restored.group_id
        || staged.group_context().ciphersuite() != CIPHERSUITE
    {
        return Err(BridgeError::InvalidState);
    }
    let group = staged
        .into_group(&restored.provider)
        .map_err(|_| BridgeError::Crypto)?;
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(StateOutput {
        roster: encode_roster(&group)?,
        epoch: group.epoch().as_u64(),
        state,
    })
}

fn seal_impl(
    state: &[u8],
    authenticated_data: &[u8],
    plaintext: &[u8],
) -> BridgeResult<SealOutput> {
    validate_aad(authenticated_data)?;
    if plaintext.is_empty() || plaintext.len() > MAX_APPLICATION_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let restored = restore(state, Stage::Group)?;
    let signer = load_signer(&restored)?;
    let mut group = load_group(&restored)?;
    group.set_aad(authenticated_data.to_vec());
    let message = group
        .create_message(&restored.provider, &signer, plaintext)
        .map_err(|_| BridgeError::Crypto)?
        .to_bytes()
        .map_err(|_| BridgeError::Codec)?;
    if message.len() > MAX_MLS_MESSAGE_SIZE {
        return Err(BridgeError::InvalidState);
    }
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(SealOutput {
        epoch: group.epoch().as_u64(),
        state,
        message,
    })
}

fn process_impl(state: &[u8], message: &[u8]) -> BridgeResult<ProcessOutput> {
    if message.is_empty() || message.len() > MAX_MLS_MESSAGE_SIZE {
        return Err(BridgeError::InvalidArgument);
    }
    let restored = restore(state, Stage::Group)?;
    let mut group = load_group(&restored)?;
    let protocol_message = MlsMessageIn::tls_deserialize_exact(message)
        .map_err(|_| BridgeError::Codec)?
        .try_into_protocol_message()
        .map_err(|_| BridgeError::Codec)?;
    let processed = group
        .process_message(&restored.provider, protocol_message)
        .map_err(|_| BridgeError::Crypto)?;
    if processed.group_id().as_slice() != restored.group_id
        || processed.aad().is_empty()
        || processed.aad().len() > MAX_AUTHENTICATED_DATA_SIZE
        || processed.credential().credential_type() != CredentialType::Basic
        || processed.credential().serialized_content().is_empty()
        || processed.credential().serialized_content().len() > MAX_IDENTITY_SIZE
    {
        return Err(BridgeError::Unsupported);
    }
    let sender_index = match processed.sender() {
        Sender::Member(index) => index.u32(),
        _ => NON_MEMBER_SENDER,
    };
    if sender_index == NON_MEMBER_SENDER {
        return Err(BridgeError::Unsupported);
    }
    let epoch = processed.epoch().as_u64();
    let authenticated_data = processed.aad().to_vec();
    let sender_credential = processed.credential().serialized_content().to_vec();
    let (kind, plaintext) = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            (CONTENT_APPLICATION, application.into_bytes())
        }
        ProcessedMessageContent::ProposalMessage(proposal) => {
            group
                .store_pending_proposal(restored.provider.storage(), *proposal)
                .map_err(|_| BridgeError::InvalidState)?;
            (CONTENT_PROPOSAL, Vec::new())
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            return Err(BridgeError::Unsupported);
        }
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            group
                .merge_staged_commit(&restored.provider, *commit)
                .map_err(|_| BridgeError::InvalidState)?;
            (CONTENT_COMMIT, Vec::new())
        }
        ProcessedMessageContent::OwnPendingCommit | ProcessedMessageContent::OwnPrivateMessage => {
            return Err(BridgeError::Unsupported);
        }
    };
    if plaintext.len() > MAX_APPLICATION_SIZE {
        return Err(BridgeError::InvalidState);
    }
    let state = encode_snapshot(
        &restored.provider,
        Stage::Group,
        &restored.group_id,
        &restored.identity,
        &restored.signer_public_key,
    )?;
    Ok(ProcessOutput {
        roster: encode_roster(&group)?,
        state,
        plaintext,
        authenticated_data,
        sender_credential,
        kind,
        sender_index,
        epoch,
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TdE2EOpenMlsBytes {
    data: *const u8,
    size: usize,
}

#[repr(C)]
pub struct TdE2EOpenMlsBuffer {
    data: *mut u8,
    size: usize,
}

impl Default for TdE2EOpenMlsBuffer {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            size: 0,
        }
    }
}

impl From<Vec<u8>> for TdE2EOpenMlsBuffer {
    fn from(value: Vec<u8>) -> Self {
        if value.is_empty() {
            return Self::default();
        }
        let mut value = value.into_boxed_slice();
        let result = Self {
            data: value.as_mut_ptr(),
            size: value.len(),
        };
        std::mem::forget(value);
        result
    }
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EOpenMlsStateResult {
    status: u32,
    epoch: u64,
    state: TdE2EOpenMlsBuffer,
    roster: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EOpenMlsKeyPackageResult {
    status: u32,
    state: TdE2EOpenMlsBuffer,
    key_package: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EOpenMlsCommitResult {
    status: u32,
    epoch: u64,
    state: TdE2EOpenMlsBuffer,
    commit: TdE2EOpenMlsBuffer,
    welcome: TdE2EOpenMlsBuffer,
    roster: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EOpenMlsSealResult {
    status: u32,
    epoch: u64,
    state: TdE2EOpenMlsBuffer,
    message: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EOpenMlsProcessResult {
    status: u32,
    kind: u32,
    sender_index: u32,
    epoch: u64,
    state: TdE2EOpenMlsBuffer,
    plaintext: TdE2EOpenMlsBuffer,
    authenticated_data: TdE2EOpenMlsBuffer,
    sender_credential: TdE2EOpenMlsBuffer,
    roster: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EHpkeSealResult {
    status: u32,
    encapsulated_key: TdE2EOpenMlsBuffer,
    ciphertext: TdE2EOpenMlsBuffer,
}

#[repr(C)]
#[derive(Default)]
pub struct TdE2EHpkeOpenResult {
    status: u32,
    plaintext: TdE2EOpenMlsBuffer,
}

unsafe fn read_input<'a>(
    value: TdE2EOpenMlsBytes,
    maximum: usize,
    allow_empty: bool,
) -> BridgeResult<&'a [u8]> {
    if value.size > maximum || (!allow_empty && value.size == 0) {
        return Err(BridgeError::InvalidArgument);
    } else if value.size == 0 {
        return Ok(&[]);
    } else if value.data.is_null() {
        return Err(BridgeError::InvalidArgument);
    }
    Ok(unsafe { std::slice::from_raw_parts(value.data, value.size) })
}

fn state_result(
    result: Result<BridgeResult<StateOutput>, Box<dyn std::any::Any + Send>>,
) -> TdE2EOpenMlsStateResult {
    match result {
        Ok(Ok(output)) => TdE2EOpenMlsStateResult {
            status: STATUS_OK,
            epoch: output.epoch,
            state: output.state.into(),
            roster: output.roster.into(),
        },
        Ok(Err(error)) => TdE2EOpenMlsStateResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EOpenMlsStateResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[no_mangle]
pub extern "C" fn td_e2e_openmls_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
/// # Safety
///
/// The buffer must be an unmodified value returned by this bridge and must be
/// released exactly once. Foreign buffers and duplicate releases are invalid.
pub unsafe extern "C" fn td_e2e_openmls_buffer_free(buffer: TdE2EOpenMlsBuffer) {
    if buffer.data.is_null() || buffer.size == 0 {
        return;
    }
    let raw = ptr::slice_from_raw_parts_mut(buffer.data, buffer.size);
    let mut value = unsafe { Box::from_raw(raw) };
    value.fill(0);
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_create_group(
    identity: TdE2EOpenMlsBytes,
    group_id: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsStateResult {
    state_result(catch_unwind(AssertUnwindSafe(|| {
        let identity = unsafe { read_input(identity, MAX_IDENTITY_SIZE, false) }?;
        let group_id = unsafe { read_input(group_id, GROUP_ID_SIZE, false) }?;
        create_group_impl(identity, group_id)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_inspect_group(
    state: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsStateResult {
    state_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        inspect_group_impl(state)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_create_key_package(
    identity: TdE2EOpenMlsBytes,
    expected_group_id: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsKeyPackageResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let identity = unsafe { read_input(identity, MAX_IDENTITY_SIZE, false) }?;
        let group_id = unsafe { read_input(expected_group_id, GROUP_ID_SIZE, false) }?;
        create_key_package_impl(identity, group_id)
    })) {
        Ok(Ok(output)) => TdE2EOpenMlsKeyPackageResult {
            status: STATUS_OK,
            state: output.state.into(),
            key_package: output.key_package.into(),
        },
        Ok(Err(error)) => TdE2EOpenMlsKeyPackageResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EOpenMlsKeyPackageResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_inspect_key_package_state(state: TdE2EOpenMlsBytes) -> u32 {
    match catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        inspect_key_package_state_impl(state)
    })) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(error)) => error.status(),
        Err(_) => STATUS_PANIC,
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_add_member(
    state: TdE2EOpenMlsBytes,
    key_package: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsCommitResult {
    commit_ffi_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let key_package = unsafe { read_input(key_package, MAX_KEY_PACKAGE_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        add_member_impl(state, key_package, aad)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_update_group(
    state: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsCommitResult {
    commit_ffi_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        update_group_impl(state, aad)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_remove_member(
    state: TdE2EOpenMlsBytes,
    leaf_index: u32,
    authenticated_data: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsCommitResult {
    commit_ffi_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        remove_member_impl(state, &[leaf_index], aad)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_remove_members(
    state: TdE2EOpenMlsBytes,
    leaf_indices_be: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsCommitResult {
    commit_ffi_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let encoded = unsafe {
            read_input(
                leaf_indices_be,
                MAX_ROSTER_MEMBERS * std::mem::size_of::<u32>(),
                false,
            )?
        };
        if encoded.len() % std::mem::size_of::<u32>() != 0 {
            return Err(BridgeError::InvalidArgument);
        }
        let indices = encoded
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect::<Vec<_>>();
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        remove_member_impl(state, &indices, aad)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_recover_fork(
    state: TdE2EOpenMlsBytes,
    own_partition_leaf_indices_be: TdE2EOpenMlsBytes,
    replacement_key_packages: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsCommitResult {
    commit_ffi_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let encoded_indices = unsafe {
            read_input(
                own_partition_leaf_indices_be,
                MAX_ROSTER_MEMBERS * std::mem::size_of::<u32>(),
                false,
            )?
        };
        if encoded_indices.len() % std::mem::size_of::<u32>() != 0 {
            return Err(BridgeError::InvalidArgument);
        }
        let indices = encoded_indices
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect::<Vec<_>>();
        let key_packages =
            unsafe { read_input(replacement_key_packages, MAX_KEY_PACKAGE_LIST_SIZE, false)? };
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        recover_fork_impl(state, &indices, key_packages, aad)
    })))
}

fn commit_ffi_result(
    result: Result<BridgeResult<CommitOutput>, Box<dyn std::any::Any + Send>>,
) -> TdE2EOpenMlsCommitResult {
    match result {
        Ok(Ok(output)) => TdE2EOpenMlsCommitResult {
            status: STATUS_OK,
            epoch: output.epoch,
            state: output.state.into(),
            commit: output.commit.into(),
            welcome: output.welcome.into(),
            roster: output.roster.into(),
        },
        Ok(Err(error)) => TdE2EOpenMlsCommitResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EOpenMlsCommitResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_join(
    state: TdE2EOpenMlsBytes,
    welcome: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsStateResult {
    state_result(catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let welcome = unsafe { read_input(welcome, MAX_WELCOME_SIZE, false) }?;
        join_impl(state, welcome)
    })))
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_seal(
    state: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
    plaintext: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsSealResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_AUTHENTICATED_DATA_SIZE, false) }?;
        let plaintext = unsafe { read_input(plaintext, MAX_APPLICATION_SIZE, false) }?;
        seal_impl(state, aad, plaintext)
    })) {
        Ok(Ok(output)) => TdE2EOpenMlsSealResult {
            status: STATUS_OK,
            epoch: output.epoch,
            state: output.state.into(),
            message: output.message.into(),
        },
        Ok(Err(error)) => TdE2EOpenMlsSealResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EOpenMlsSealResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_openmls_process(
    state: TdE2EOpenMlsBytes,
    message: TdE2EOpenMlsBytes,
) -> TdE2EOpenMlsProcessResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { read_input(state, MAX_STATE_SIZE, false) }?;
        let message = unsafe { read_input(message, MAX_MLS_MESSAGE_SIZE, false) }?;
        process_impl(state, message)
    })) {
        Ok(Ok(output)) => TdE2EOpenMlsProcessResult {
            status: STATUS_OK,
            kind: output.kind,
            sender_index: output.sender_index,
            epoch: output.epoch,
            state: output.state.into(),
            plaintext: output.plaintext.into(),
            authenticated_data: output.authenticated_data.into(),
            sender_credential: output.sender_credential.into(),
            roster: output.roster.into(),
        },
        Ok(Err(error)) => TdE2EOpenMlsProcessResult {
            status: error.status(),
            kind: CONTENT_NONE,
            sender_index: NON_MEMBER_SENDER,
            ..Default::default()
        },
        Err(_) => TdE2EOpenMlsProcessResult {
            status: STATUS_PANIC,
            kind: CONTENT_NONE,
            sender_index: NON_MEMBER_SENDER,
            ..Default::default()
        },
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_hpke_seal(
    recipient_public_key: TdE2EOpenMlsBytes,
    info: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
    plaintext: TdE2EOpenMlsBytes,
) -> TdE2EHpkeSealResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let public_key = unsafe { read_input(recipient_public_key, HPKE_KEY_SIZE, false) }?;
        let info = unsafe { read_input(info, MAX_HPKE_INFO_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_HPKE_AAD_SIZE, false) }?;
        let plaintext = unsafe { read_input(plaintext, MAX_HPKE_PLAINTEXT_SIZE, false) }?;
        hpke_seal_impl(public_key, info, aad, plaintext)
    })) {
        Ok(Ok(output)) => TdE2EHpkeSealResult {
            status: STATUS_OK,
            encapsulated_key: output.encapsulated_key.into(),
            ciphertext: output.ciphertext.into(),
        },
        Ok(Err(error)) => TdE2EHpkeSealResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EHpkeSealResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[no_mangle]
/// # Safety
///
/// Every non-empty input view must remain readable for its declared size until
/// this call returns. Empty views may use a null pointer.
pub unsafe extern "C" fn td_e2e_hpke_open(
    recipient_private_key: TdE2EOpenMlsBytes,
    encapsulated_key: TdE2EOpenMlsBytes,
    info: TdE2EOpenMlsBytes,
    authenticated_data: TdE2EOpenMlsBytes,
    ciphertext: TdE2EOpenMlsBytes,
) -> TdE2EHpkeOpenResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let private_key = unsafe { read_input(recipient_private_key, HPKE_KEY_SIZE, false) }?;
        let encapsulated_key = unsafe { read_input(encapsulated_key, HPKE_KEY_SIZE, false) }?;
        let info = unsafe { read_input(info, MAX_HPKE_INFO_SIZE, false) }?;
        let aad = unsafe { read_input(authenticated_data, MAX_HPKE_AAD_SIZE, false) }?;
        let ciphertext =
            unsafe { read_input(ciphertext, MAX_HPKE_PLAINTEXT_SIZE + HPKE_TAG_SIZE, false) }?;
        hpke_open_impl(private_key, encapsulated_key, info, aad, ciphertext)
    })) {
        Ok(Ok(plaintext)) => TdE2EHpkeOpenResult {
            status: STATUS_OK,
            plaintext: plaintext.into(),
        },
        Ok(Err(error)) => TdE2EHpkeOpenResult {
            status: error.status(),
            ..Default::default()
        },
        Err(_) => TdE2EHpkeOpenResult {
            status: STATUS_PANIC,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_members_survive_every_snapshot_boundary() {
        let group_id = [7_u8; GROUP_ID_SIZE];
        let alice = create_group_impl(b"alice-client", &group_id).unwrap();
        let bob_package = create_key_package_impl(b"bob-client", &group_id).unwrap();
        let added = add_member_impl(
            &alice.state,
            &bob_package.key_package,
            b"authenticated-add-transition",
        )
        .unwrap();
        assert_eq!(added.epoch, 1);
        let bob = join_impl(&bob_package.state, &added.welcome).unwrap();
        assert_eq!(bob.epoch, 1);
        assert_eq!(bob.roster, added.roster);

        let sealed =
            seal_impl(&added.state, b"bound-application-metadata", b"content-key").unwrap();
        let opened = process_impl(&bob.state, &sealed.message).unwrap();
        assert_eq!(opened.kind, CONTENT_APPLICATION);
        assert_eq!(opened.sender_index, 0);
        assert_eq!(opened.epoch, 1);
        assert_eq!(opened.plaintext, b"content-key");
        assert_eq!(opened.authenticated_data, b"bound-application-metadata");
        assert_eq!(opened.sender_credential, b"alice-client");

        let reply =
            seal_impl(&opened.state, b"bound-reply-metadata", b"reply-content-key").unwrap();
        let reply_opened = process_impl(&sealed.state, &reply.message).unwrap();
        assert_eq!(reply_opened.sender_index, 1);
        assert_eq!(reply_opened.plaintext, b"reply-content-key");
        assert_eq!(reply_opened.sender_credential, b"bob-client");
        assert!(process_impl(&opened.state, &sealed.message).is_err());
    }

    #[test]
    fn fork_recovery_readds_the_complement_partition() {
        let group_id = [9_u8; GROUP_ID_SIZE];
        let alice = create_group_impl(b"alice-client", &group_id).unwrap();
        let bob_package = create_key_package_impl(b"bob-client", &group_id).unwrap();
        let added_bob =
            add_member_impl(&alice.state, &bob_package.key_package, b"add-bob").unwrap();
        let bob = join_impl(&bob_package.state, &added_bob.welcome).unwrap();
        let charlie_package = create_key_package_impl(b"charlie-client", &group_id).unwrap();
        let alice_branch = add_member_impl(
            &added_bob.state,
            &charlie_package.key_package,
            b"alice-adds-charlie",
        )
        .unwrap();
        let bob_branch = add_member_impl(
            &bob.state,
            &charlie_package.key_package,
            b"bob-adds-charlie",
        )
        .unwrap();
        let charlie = join_impl(&charlie_package.state, &alice_branch.welcome).unwrap();
        assert_eq!(alice_branch.epoch, bob_branch.epoch);
        assert!(process_impl(&bob_branch.state, &alice_branch.commit).is_err());

        let bob_replacement = create_key_package_impl(b"bob-client", &group_id).unwrap();
        let mut packages = Vec::new();
        append_u32(&mut packages, 1).unwrap();
        append_u32(&mut packages, bob_replacement.key_package.len()).unwrap();
        packages.extend_from_slice(&bob_replacement.key_package);
        let recovered = recover_fork_impl(
            &alice_branch.state,
            &[0, 2],
            &packages,
            b"owner-resolves-complete-fork-set",
        )
        .unwrap();
        let bob_rejoined = join_impl(&bob_replacement.state, &recovered.welcome).unwrap();
        let charlie_recovered = process_impl(&charlie.state, &recovered.commit).unwrap();
        assert_eq!(charlie_recovered.kind, CONTENT_COMMIT);
        assert_eq!(recovered.epoch, 3);
        assert_eq!(recovered.roster, bob_rejoined.roster);
        assert_eq!(recovered.roster, charlie_recovered.roster);

        let sealed = seal_impl(
            &recovered.state,
            b"post-fork-application",
            b"converged-content",
        )
        .unwrap();
        assert_eq!(
            process_impl(&bob_rejoined.state, &sealed.message)
                .unwrap()
                .plaintext,
            b"converged-content"
        );
        assert_eq!(
            process_impl(&charlie_recovered.state, &sealed.message)
                .unwrap()
                .plaintext,
            b"converged-content"
        );
    }

    #[test]
    fn corrupt_and_noncanonical_snapshots_fail_closed() {
        let group_id = [8_u8; GROUP_ID_SIZE];
        let state = create_group_impl(b"client", &group_id).unwrap().state;
        let mut trailing = state.clone();
        trailing.push(0);
        assert!(decode_snapshot(&trailing).is_err());
        let mut wrong_magic = state;
        wrong_magic[0] ^= 1;
        assert!(decode_snapshot(&wrong_magic).is_err());
    }

    #[test]
    fn archive_hpke_round_trip_binds_context() {
        let mut provider = hpke();
        let (private_key, public_key) = provider.generate_key_pair().unwrap().into_keys();
        let first = hpke_seal_impl(
            public_key.as_slice(),
            b"TDE2E/archive-grant/v1",
            b"authenticated grant fields",
            b"archive epoch keys",
        )
        .unwrap();
        let second = hpke_seal_impl(
            public_key.as_slice(),
            b"TDE2E/archive-grant/v1",
            b"authenticated grant fields",
            b"archive epoch keys",
        )
        .unwrap();
        assert_ne!(first.encapsulated_key, second.encapsulated_key);
        assert_ne!(first.ciphertext, second.ciphertext);
        let opened = hpke_open_impl(
            private_key.as_slice(),
            &first.encapsulated_key,
            b"TDE2E/archive-grant/v1",
            b"authenticated grant fields",
            &first.ciphertext,
        )
        .unwrap();
        assert_eq!(opened, b"archive epoch keys");
        assert!(hpke_open_impl(
            private_key.as_slice(),
            &first.encapsulated_key,
            b"TDE2E/archive-grant/v1",
            b"modified grant fields",
            &first.ciphertext,
        )
        .is_err());
    }
}
