use crate::randomness::GeneralRng;
use crate::randomness::SecureRng;
use crate::security::BitsOfSecurity;
use crate::Enrichable;
use rug::Integer;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an `AsymmetricCryptosystem` will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
pub trait AsymmetricCryptosystem<'pk> {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext: Enrichable<'pk, Self::PublicKey, Self::RichCiphertext<'pk>>;
    /// Rich representation of a ciphertext that associates it with the corresponding public key.
    /// This allows for performing homomorphic operations using operator overloading, among others.
    type RichCiphertext<'p>;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the decryption key.
    type SecretKey;

    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_param`.
    fn generate_keys<R: SecureRng>(
        security_param: &BitsOfSecurity,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: SecureRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext;

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt<'p>(
        rich_ciphertext: &Self::RichCiphertext<'p>,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext;
}

/// A Signature Scheme is a cryptosystem that implements signing and verification functionality.
/// Only the owner of the private key can create a valid signature on a message, while anyone with the public key
/// can verify the signature
pub trait SignatureScheme<'pk> {
    /// The type of the plaintexts to be signed.
    type Plaintext;
    /// The type of the signatures.
    type Signature: Enrichable<'pk, Self::PublicKey, Self::RichSignature<'pk>>;
    /// Rich representation of a signature that associates it with the corresponding public key.
    /// Allows performing easy verification of the signature with the associated public key.
    type RichSignature<'p>;

    /// The type of the verification key.
    type PublicKey;
    /// The type of the signing key.
    type SecretKey;

    /// Sign the plaintext using the secret key.
    fn sign<'p>(
        plaintext: &Self::Plaintext,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Self::Signature;

    /// Verify a signature on a message using the public key of the signature
    fn verify<'p>(signature: &Self::RichSignature<'p>, plaintext: &Self::Plaintext) -> bool;
}

/// A trait to encrypt using own supplied randomness
pub trait EncryptRaw<'pk> {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext: Enrichable<'pk, Self::PublicKey, Self::RichCiphertext<'pk>>;
    /// Rich representation of a ciphertext that associates it with the corresponding public key.
    /// This allows for performing homomorphic operations using operator overloading, among others.
    type RichCiphertext<'p>;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the decryption key.
    type SecretKey;

    /// Method to encrypt paillier with own randomness
    fn encrypt_raw(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        r: Integer,
    ) -> Self::Ciphertext;
}
