impl CryptoBackend for OsCryptoBackend {
    fn random_bytes(&mut self, length: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0; length];
        OsRandomSource.fill(&mut output)?;
        Ok(output)
    }

    fn generate_ed25519_keypair(&mut self) -> Result<Ed25519KeyPair, CryptoError> {
        ed25519_keypair(&mut OsRandomSource)
    }

    fn ed25519_sign(
        &self,
        secret_key: &Ed25519SecretKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, CryptoError> {
        let secret = <[u8; ED25519_SECRET_KEY_LEN]>::try_from(secret_key.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Ed25519Signature::from_array(
            SigningKey::from_bytes(&secret).sign(message).to_bytes(),
        ))
    }

    fn ed25519_verify(
        &self,
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<bool, CryptoError> {
        let key = VerifyingKey::from_bytes(&public_key.into_array())
            .map_err(|_| CryptoError::InvalidKey)?;
        let signature = Signature::from_bytes(&signature.into_array());
        Ok(key.verify(message, &signature).is_ok())
    }

    fn generate_x25519_keypair(&mut self) -> Result<X25519KeyPair, CryptoError> {
        x25519_keypair(&mut OsRandomSource)
    }

    fn x25519_encapsulate(
        &mut self,
        recipient: &X25519PublicKey,
    ) -> Result<(X25519PublicKey, SharedSecret), CryptoError> {
        x25519_encapsulate_with_rng(&mut OsRandomSource, recipient)
    }

    fn x25519_decapsulate(
        &self,
        secret_key: &X25519SecretKey,
        ciphertext: &X25519PublicKey,
    ) -> Result<SharedSecret, CryptoError> {
        let secret = StaticSecret::from(
            <[u8; X25519PublicKey::LEN]>::try_from(secret_key.as_bytes())
                .map_err(|_| CryptoError::InvalidKey)?,
        );
        let shared = secret.diffie_hellman(&X25519::from(ciphertext.into_array()));
        x25519_shared_secret(shared.to_bytes())
    }

    fn generate_mlkem768_keypair(&mut self) -> Result<MlKemKeyPair, CryptoError> {
        mlkem_keypair(&mut OsRandomSource)
    }

    fn mlkem768_encapsulate(
        &mut self,
        recipient: &MlKemPublicKey,
    ) -> Result<(MlKemCiphertext, SharedSecret), CryptoError> {
        mlkem_encapsulate(&mut OsRandomSource, recipient)
    }

    fn mlkem768_decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> Result<SharedSecret, CryptoError> {
        mlkem_decapsulate(secret_key, ciphertext)
    }

    fn hkdf_extract(&self, domain: &[u8], ikm: &[u8]) -> Result<SharedSecret, CryptoError> {
        let framed_ikm = framed(domain, ikm)?;
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&HKDF_ZERO_SALT), &framed_ikm);
        SharedSecret::from_bytes(prk.as_ref()).map_err(|_| CryptoError::InvalidKey)
    }

    fn hkdf_expand_32(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<SharedSecret, CryptoError> {
        SharedSecret::from_bytes(&hkdf_expand(prk, domain, info, SHARED_SECRET_LEN)?)
            .map_err(|_| CryptoError::InvalidKey)
    }

    fn derive_message_key(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<MessageKey, CryptoError> {
        MessageKey::from_bytes(&hkdf_expand(prk, domain, info, MessageKey::LEN)?)
            .map_err(|_| CryptoError::InvalidKey)
    }

    fn derive_nonce(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<Nonce, CryptoError> {
        Nonce::from_bytes(&hkdf_expand(prk, domain, info, NONCE_LEN)?)
            .map_err(|_| CryptoError::InvalidKey)
    }

    fn sha256(&self, message: &[u8]) -> PackageHash {
        PackageHash::from_array(Sha256::digest(message).into())
    }

    fn hmac_sha256(&self, key: &SharedSecret, message: &[u8]) -> HmacTag {
        let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts a 32-byte key");
        mac.update(message);
        HmacTag::from_bytes(&mac.finalize().into_bytes()).expect("HMAC output is 32 bytes")
    }

    fn seal(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        let nonce = chacha20poly1305::Nonce::try_from(nonce.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn open(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        let nonce = chacha20poly1305::Nonce::try_from(nonce.as_bytes())
            .map_err(|_| CryptoError::InvalidKey)?;
        cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}
use crate::foundation::*;
use crate::primitives::{
    ed25519_keypair, framed, hkdf_expand, mlkem_decapsulate, mlkem_encapsulate, mlkem_keypair,
    x25519_encapsulate_with_rng, x25519_keypair, x25519_shared_secret,
};
use crate::rng::{OsCryptoBackend, OsRandomSource, RandomSource};
use crate::traits::CryptoBackend;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use linkchat_types::{
    MessageKey, MlKemCiphertext, NONCE_LEN, Nonce, PackageHash, SharedSecret, X25519PublicKey,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519, StaticSecret};
