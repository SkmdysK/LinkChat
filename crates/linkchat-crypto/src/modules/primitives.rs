use crate::foundation::*;
use crate::rng::{FixedRandomSource, RandomSource};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate, KeyExport};
use linkchat_types::{MlKemCiphertext, SharedSecret, X25519PublicKey};
use ml_kem::{
    DecapsulationKey768, EncapsulationKey768, MlKem768, Seed,
    kem::{Ciphertext as MlKemCiphertextBytes, Key as MlKemKey},
    ml_kem_768::Ciphertext as MlKem768Ciphertext,
};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519, StaticSecret};
use zeroize::Zeroize;

pub(crate) fn ed25519_keypair<R: RandomSource>(rng: &mut R) -> Result<Ed25519KeyPair, CryptoError> {
    let mut secret = [0; ED25519_SECRET_KEY_LEN];
    rng.fill(&mut secret)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let result = Ed25519KeyPair {
        secret_key: Ed25519SecretKey::from_bytes(&secret)?,
        public_key: Ed25519PublicKey::from_array(signing_key.verifying_key().to_bytes()),
    };
    secret.zeroize();
    Ok(result)
}

pub(crate) fn x25519_keypair<R: RandomSource>(rng: &mut R) -> Result<X25519KeyPair, CryptoError> {
    let mut secret = [0; X25519PublicKey::LEN];
    rng.fill(&mut secret)?;
    let static_secret = StaticSecret::from(secret);
    let result = X25519KeyPair {
        secret_key: X25519SecretKey::from_bytes(&secret)?,
        public_key: X25519PublicKey::from_array(X25519::from(&static_secret).to_bytes()),
    };
    secret.zeroize();
    Ok(result)
}

pub(crate) fn x25519_shared_secret(
    bytes: [u8; SHARED_SECRET_LEN],
) -> Result<SharedSecret, CryptoError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::LowOrderPoint);
    }
    SharedSecret::from_bytes(&bytes).map_err(|_| CryptoError::InvalidKey)
}

/// Reconstructs the public X25519 value for a typed private key.
///
/// This is used by the core-owned storage decoder to verify that restored
/// private material still matches the public Receiver Package projection.
pub fn x25519_public_from_secret(
    secret_key: &X25519SecretKey,
) -> Result<X25519PublicKey, CryptoError> {
    let secret = <[u8; X25519PublicKey::LEN]>::try_from(secret_key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    let static_secret = StaticSecret::from(secret);
    Ok(X25519PublicKey::from_array(
        X25519::from(&static_secret).to_bytes(),
    ))
}

pub(crate) fn x25519_encapsulate_with_rng<R: RandomSource>(
    rng: &mut R,
    recipient: &X25519PublicKey,
) -> Result<(X25519PublicKey, SharedSecret), CryptoError> {
    let mut secret = [0; X25519PublicKey::LEN];
    rng.fill(&mut secret)?;
    let mut fixed_rng = FixedRandomSource::new(secret);
    secret.zeroize();
    let ephemeral = EphemeralSecret::random_from_rng(&mut fixed_rng);
    let public = X25519::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&X25519::from(recipient.into_array()));
    Ok((
        X25519PublicKey::from_array(public.to_bytes()),
        x25519_shared_secret(shared.to_bytes())?,
    ))
}

pub(crate) fn mlkem_keypair<R: RandomSource>(rng: &mut R) -> Result<MlKemKeyPair, CryptoError> {
    let mut seed_bytes = [0; ML_KEM_768_SEED_LEN];
    rng.fill(&mut seed_bytes)?;
    let seed = Seed::try_from(seed_bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = DecapsulationKey768::from_seed(seed);
    let public_key =
        MlKemPublicKey::from_bytes(decapsulation_key.encapsulation_key().to_bytes().as_ref())?;
    let result = MlKemKeyPair {
        secret_key: MlKemSecretKey::from_bytes(&seed_bytes)?,
        public_key,
    };
    seed_bytes.zeroize();
    Ok(result)
}

pub(crate) fn mlkem_encapsulate<R: RandomSource>(
    rng: &mut R,
    recipient: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, SharedSecret), CryptoError> {
    let key: MlKemKey<EncapsulationKey768> =
        <MlKemKey<EncapsulationKey768>>::try_from(recipient.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
    let encapsulation_key = EncapsulationKey768::new(&key).map_err(|_| CryptoError::InvalidKey)?;
    let mut randomness = [0; SHARED_SECRET_LEN];
    rng.fill(&mut randomness)?;
    let mut fixed_rng = FixedRandomSource::new(randomness);
    let (ciphertext, shared) = encapsulation_key.encapsulate_with_rng(&mut fixed_rng);
    randomness.zeroize();
    Ok((
        MlKemCiphertext::from_bytes(ciphertext.as_ref())
            .map_err(|_| CryptoError::InvalidCiphertext)?,
        SharedSecret::from_bytes(shared.as_ref()).map_err(|_| CryptoError::InvalidKey)?,
    ))
}

pub(crate) fn mlkem_decapsulate(
    secret_key: &MlKemSecretKey,
    ciphertext: &MlKemCiphertext,
) -> Result<SharedSecret, CryptoError> {
    let seed = Seed::try_from(secret_key.as_bytes()).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = DecapsulationKey768::from_seed(seed);
    let ciphertext_bytes: MlKem768Ciphertext =
        <MlKemCiphertextBytes<MlKem768>>::try_from(ciphertext.as_bytes())
            .map_err(|_| CryptoError::InvalidCiphertext)?;
    let shared = decapsulation_key.decapsulate(&ciphertext_bytes);
    SharedSecret::from_bytes(shared.as_ref()).map_err(|_| CryptoError::InvalidKey)
}

/// Reconstructs the public ML-KEM-768 value for a typed private seed.
pub fn mlkem768_public_from_secret(
    secret_key: &MlKemSecretKey,
) -> Result<MlKemPublicKey, CryptoError> {
    let seed = Seed::try_from(secret_key.as_bytes()).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = DecapsulationKey768::from_seed(seed);
    MlKemPublicKey::from_bytes(decapsulation_key.encapsulation_key().to_bytes().as_ref())
}

pub(crate) fn framed(domain: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let domain_len = u16::try_from(domain.len()).map_err(|_| CryptoError::InvalidKdfLength)?;
    let value_len = u32::try_from(value.len()).map_err(|_| CryptoError::InvalidKdfLength)?;
    let mut result = Vec::with_capacity(2 + domain.len() + 4 + value.len());
    result.extend_from_slice(&domain_len.to_be_bytes());
    result.extend_from_slice(domain);
    result.extend_from_slice(&value_len.to_be_bytes());
    result.extend_from_slice(value);
    Ok(result)
}

pub(crate) fn hkdf_expand(
    prk: &SharedSecret,
    domain: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_bytes()).map_err(|_| CryptoError::InvalidKey)?;
    let framed_info = framed(domain, info)?;
    let mut output = vec![0; length];
    hkdf.expand(&framed_info, &mut output)
        .map_err(|_| CryptoError::InvalidKdfLength)?;
    Ok(output)
}
