use crate::foundation::*;
use crate::primitives::{
    ed25519_keypair, hkdf_expand, mlkem_encapsulate, mlkem_keypair, x25519_encapsulate_with_rng,
    x25519_keypair,
};
use crate::rng::RandomSource;
use crate::{CryptoBackend, OsCryptoBackend};
use linkchat_types::{
    HASH_LEN, ML_KEM_768_CIPHERTEXT_LEN, MessageKey, MlKemCiphertext, Nonce, PackageHash,
    SharedSecret, X25519PublicKey,
};
use sha2::{Digest, Sha256};

struct DeterministicRandomSource {
    seed: [u8; 32],
    counter: u64,
}

impl DeterministicRandomSource {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

impl RandomSource for DeterministicRandomSource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut offset = 0;
        while offset < output.len() {
            let mut hash = Sha256::new();
            hash.update(self.seed);
            hash.update(self.counter.to_be_bytes());
            let block: [u8; 32] = hash.finalize().into();
            let take = (output.len() - offset).min(block.len());
            output[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(CryptoError::RandomnessUnavailable)?;
        }
        Ok(())
    }
}

struct DeterministicCryptoBackend {
    rng: DeterministicRandomSource,
}

impl DeterministicCryptoBackend {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: DeterministicRandomSource::new(seed),
        }
    }
}

impl CryptoBackend for DeterministicCryptoBackend {
    fn random_bytes(&mut self, length: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0; length];
        self.rng.fill(&mut output)?;
        Ok(output)
    }

    fn generate_ed25519_keypair(&mut self) -> Result<Ed25519KeyPair, CryptoError> {
        ed25519_keypair(&mut self.rng)
    }
    fn ed25519_sign(
        &self,
        key: &Ed25519SecretKey,
        msg: &[u8],
    ) -> Result<Ed25519Signature, CryptoError> {
        OsCryptoBackend.ed25519_sign(key, msg)
    }
    fn ed25519_verify(
        &self,
        key: &Ed25519PublicKey,
        msg: &[u8],
        sig: &Ed25519Signature,
    ) -> Result<bool, CryptoError> {
        OsCryptoBackend.ed25519_verify(key, msg, sig)
    }
    fn generate_x25519_keypair(&mut self) -> Result<X25519KeyPair, CryptoError> {
        x25519_keypair(&mut self.rng)
    }
    fn x25519_encapsulate(
        &mut self,
        recipient: &X25519PublicKey,
    ) -> Result<(X25519PublicKey, SharedSecret), CryptoError> {
        x25519_encapsulate_with_rng(&mut self.rng, recipient)
    }
    fn x25519_decapsulate(
        &self,
        key: &X25519SecretKey,
        ct: &X25519PublicKey,
    ) -> Result<SharedSecret, CryptoError> {
        OsCryptoBackend.x25519_decapsulate(key, ct)
    }
    fn generate_mlkem768_keypair(&mut self) -> Result<MlKemKeyPair, CryptoError> {
        mlkem_keypair(&mut self.rng)
    }
    fn mlkem768_encapsulate(
        &mut self,
        key: &MlKemPublicKey,
    ) -> Result<(MlKemCiphertext, SharedSecret), CryptoError> {
        mlkem_encapsulate(&mut self.rng, key)
    }
    fn mlkem768_decapsulate(
        &self,
        key: &MlKemSecretKey,
        ct: &MlKemCiphertext,
    ) -> Result<SharedSecret, CryptoError> {
        OsCryptoBackend.mlkem768_decapsulate(key, ct)
    }
    fn hkdf_extract(&self, domain: &[u8], ikm: &[u8]) -> Result<SharedSecret, CryptoError> {
        OsCryptoBackend.hkdf_extract(domain, ikm)
    }
    fn hkdf_expand_32(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<SharedSecret, CryptoError> {
        OsCryptoBackend.hkdf_expand_32(prk, domain, info)
    }
    fn derive_message_key(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<MessageKey, CryptoError> {
        OsCryptoBackend.derive_message_key(prk, domain, info)
    }
    fn derive_nonce(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<Nonce, CryptoError> {
        OsCryptoBackend.derive_nonce(prk, domain, info)
    }
    fn sha256(&self, msg: &[u8]) -> PackageHash {
        OsCryptoBackend.sha256(msg)
    }
    fn hmac_sha256(&self, key: &SharedSecret, msg: &[u8]) -> HmacTag {
        OsCryptoBackend.hmac_sha256(key, msg)
    }
    fn seal(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        OsCryptoBackend.seal(key, nonce, aad, msg)
    }
    fn open(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        OsCryptoBackend.open(key, nonce, aad, ct)
    }
}

#[test]
fn deterministic_rng_is_test_only_and_reproducible() {
    let mut a = DeterministicCryptoBackend::new([7; 32]);
    let mut b = DeterministicCryptoBackend::new([7; 32]);
    let a_x25519 = a.generate_x25519_keypair().unwrap();
    let b_x25519 = b.generate_x25519_keypair().unwrap();
    assert_eq!(a_x25519.public_key, b_x25519.public_key);
    assert_eq!(
        a_x25519.secret_key.as_bytes(),
        b_x25519.secret_key.as_bytes()
    );
    let a_mlkem = a.generate_mlkem768_keypair().unwrap();
    let b_mlkem = b.generate_mlkem768_keypair().unwrap();
    assert_eq!(a_mlkem.public_key, b_mlkem.public_key);
    assert_eq!(a_mlkem.secret_key.as_bytes(), b_mlkem.secret_key.as_bytes());
}

#[test]
fn ed25519_round_trip() {
    let mut backend = DeterministicCryptoBackend::new([1; 32]);
    let pair = backend.generate_ed25519_keypair().unwrap();
    let signature = backend.ed25519_sign(&pair.secret_key, b"linkchat").unwrap();
    assert!(
        backend
            .ed25519_verify(&pair.public_key, b"linkchat", &signature)
            .unwrap()
    );
    assert!(
        !backend
            .ed25519_verify(&pair.public_key, b"changed", &signature)
            .unwrap()
    );
}

#[test]
fn x25519_rejects_low_order_and_round_trips() {
    let mut backend = DeterministicCryptoBackend::new([2; 32]);
    let receiver = backend.generate_x25519_keypair().unwrap();
    let (ct, sent) = backend.x25519_encapsulate(&receiver.public_key).unwrap();
    let received = backend
        .x25519_decapsulate(&receiver.secret_key, &ct)
        .unwrap();
    assert_eq!(sent.as_bytes(), received.as_bytes());
    assert!(matches!(
        backend.x25519_decapsulate(&receiver.secret_key, &X25519PublicKey::from_array([0; 32])),
        Err(CryptoError::LowOrderPoint)
    ));
    let mut low_order_one = [0; 32];
    low_order_one[0] = 1;
    assert!(matches!(
        backend.x25519_decapsulate(
            &receiver.secret_key,
            &X25519PublicKey::from_array(low_order_one)
        ),
        Err(CryptoError::LowOrderPoint)
    ));
    assert!(matches!(
        backend.x25519_encapsulate(&X25519PublicKey::from_array([0; 32])),
        Err(CryptoError::LowOrderPoint)
    ));
}

#[test]
fn mlkem768_round_trip_and_length_boundary() {
    let mut backend = DeterministicCryptoBackend::new([3; 32]);
    let receiver = backend.generate_mlkem768_keypair().unwrap();
    let (ct, sent) = backend.mlkem768_encapsulate(&receiver.public_key).unwrap();
    let received = backend
        .mlkem768_decapsulate(&receiver.secret_key, &ct)
        .unwrap();
    assert_eq!(sent.as_bytes(), received.as_bytes());
    assert_eq!(ct.as_bytes().len(), ML_KEM_768_CIPHERTEXT_LEN);
    assert!(MlKemCiphertext::from_bytes(&[0; ML_KEM_768_CIPHERTEXT_LEN - 1]).is_err());
}

#[test]
fn hash_kdf_hmac_and_aead_have_fixed_boundaries() {
    let backend = OsCryptoBackend::new();
    assert_eq!(
        backend.sha256(b"abc").as_bytes(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
    let prk = backend.hkdf_extract(b"LinkChat/test/v1", b"ikm").unwrap();
    let key = backend
        .derive_message_key(&prk, b"LinkChat/message/v1", b"context")
        .unwrap();
    let nonce = backend
        .derive_nonce(&prk, b"LinkChat/nonce/v1", b"context")
        .unwrap();
    let ciphertext = backend.seal(&key, &nonce, b"aad", b"plaintext").unwrap();
    assert_eq!(
        backend.open(&key, &nonce, b"aad", &ciphertext).unwrap(),
        b"plaintext"
    );
    assert_eq!(
        backend.open(&key, &nonce, b"bad-aad", &ciphertext),
        Err(CryptoError::AuthenticationFailed)
    );
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    assert_eq!(
        backend.open(&key, &nonce, b"aad", &tampered),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        backend.hmac_sha256(&prk, b"message").as_bytes().len(),
        HASH_LEN
    );
}

#[test]
fn hkdf_sha256_domain_framing_known_answer() {
    let backend = OsCryptoBackend::new();
    let ikm = [0x0b; 22];
    let prk = backend.hkdf_extract(b"", &ikm).unwrap();
    assert_eq!(
        prk.as_bytes(),
        &[
            0x12, 0xf5, 0x40, 0x1c, 0x0a, 0x26, 0xad, 0x74, 0xf3, 0x2c, 0x27, 0x1b, 0x14, 0xc0,
            0xbe, 0x4e, 0xa2, 0x1b, 0xb1, 0x4c, 0xa2, 0x75, 0xcb, 0x38, 0x97, 0x50, 0x22, 0x26,
            0xe5, 0xa1, 0x15, 0x56,
        ]
    );
    let okm = hkdf_expand(
        &prk,
        b"",
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        SHARED_SECRET_LEN,
    )
    .unwrap();
    assert_eq!(
        &okm,
        &[
            0x07, 0x33, 0x9d, 0x00, 0xd3, 0x8b, 0x00, 0xf3, 0xaf, 0x6c, 0x4b, 0xa7, 0xa7, 0x75,
            0x68, 0x2d, 0x2b, 0xf0, 0x3d, 0x54, 0xb5, 0x3b, 0xf2, 0x7e, 0xe3, 0xb9, 0x9b, 0xf1,
            0x35, 0x15, 0x5d, 0x85,
        ]
    );
    let nonce_a = backend
        .derive_nonce(&prk, b"LinkChat/nonce/v1", b"context")
        .unwrap();
    let nonce_b = backend
        .derive_nonce(&prk, b"LinkChat/header-nonce/v1", b"context")
        .unwrap();
    assert_ne!(nonce_a, nonce_b);
    assert_eq!(
        backend.derive_nonce(&prk, b"LinkChat/nonce/v1", b"context"),
        Ok(nonce_a)
    );
    assert!(matches!(
        backend.hkdf_extract(&vec![0; u16::MAX as usize + 1], b"ikm"),
        Err(CryptoError::InvalidKdfLength)
    ));
}

#[test]
fn hmac_sha256_known_answer() {
    let backend = OsCryptoBackend::new();
    let key = SharedSecret::from_array([0x0b; 32]);
    let tag = backend.hmac_sha256(&key, b"Hi There");
    assert_eq!(
        tag.as_bytes(),
        &[
            0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b,
            0xbd, 0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96,
            0xa0, 0xb6, 0x8c, 0xf7,
        ]
    );
}
