//! Here is an example of how to generates a key pair and encrypt a plaintext integer using the Paillier public key.
//! ```
//! use scicrypt_traits::randomness::GeneralRng;
//! use scicrypt_he::cryptosystems::paillier::Paillier;
//! use scicrypt_traits::security::BitsOfSecurity;
//! use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
//! use rug::Integer;
//! use rand_core::OsRng;
//!
//! let mut rng = GeneralRng::new(OsRng);
//! let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
//! let (public_key, secret_key) = paillier.generate_keys(&mut rng);
//! let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
//! ```

use rug::Integer;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};
use std::ops::Rem;

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// Public key for the Paillier cryptosystem.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PaillierPK {
    /// Public modulus n for encryption
    pub n: Integer,
    /// Public modulus n squared (i.e. n^2)
    pub n_squared: Integer,
}
/// Decryption key for the Paillier cryptosystem.
#[derive(Serialize, Deserialize, Clone)]
pub struct PaillierSK {
    lambda: Integer,
    mu: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PaillierCiphertext {
    /// Encrypted message (Ciphertext)
    pub c: Integer,
}

impl Associable<PaillierPK> for PaillierCiphertext {}

impl AsymmetricCryptosystem for Paillier {
    type PublicKey = PaillierPK;
    type SecretKey = PaillierSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        Paillier {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    /// Generates a fresh Paillier keypair.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// let mut rng = GeneralRng::new(OsRng);
    /// let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// ```
    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (PaillierPK, PaillierSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        let n_squared = Integer::from(n.square_ref());

        (PaillierPK { n, n_squared }, PaillierSK { lambda, mu })
    }
}

impl EncryptionKey for PaillierPK {
    type Input = Integer;
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;
    type Randomness = Integer;

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        PaillierCiphertext {
            c: ((Integer::from(plaintext) * &self.n) + 1) % &self.n_squared,
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        ciphertext: Self::Ciphertext,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        let r = Integer::from(Integer::random_below_ref(&self.n, &mut rng.rug_rng()));

        self.randomize_with(ciphertext, &r)
    }

    fn randomize_with(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        let randomizer = randomness
            .to_owned()
            .secure_pow_mod(&self.n, &self.n_squared);

        PaillierCiphertext {
            c: Integer::from(&ciphertext.c * &randomizer).rem(&self.n_squared),
        }
    }
}

impl DecryptionKey<PaillierPK> for PaillierSK {
    /// Decrypts a rich Paillier ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(&self, public_key: &PaillierPK, ciphertext: &PaillierCiphertext) -> Integer {
        let n_squared = Integer::from(public_key.n.square_ref());

        let mut inner = Integer::from(ciphertext.c.secure_pow_mod_ref(&self.lambda, &n_squared));
        inner -= 1;
        inner /= &public_key.n;
        inner *= &self.mu;

        inner.rem(&public_key.n)
    }

    fn decrypt_identity_raw(
        &self,
        public_key: &PaillierPK,
        ciphertext: &<PaillierPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        // TODO: This can be optimized
        self.decrypt_raw(public_key, ciphertext) == 0
    }
}

impl HomomorphicAddition for PaillierPK {
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: Integer::from(&ciphertext_a.c * &ciphertext_b.c)
                .rem(Integer::from(self.n.square_ref())),
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        let modulus = Integer::from(self.n.square_ref());

        PaillierCiphertext {
            c: Integer::from(ciphertext.c.pow_mod_ref(input, &modulus).unwrap()),
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        let modulus = Integer::from(self.n.square_ref());
        PaillierCiphertext {
            c: Integer::from(
                &ciphertext_a.c * &Integer::from(ciphertext_b.c.invert_ref(&modulus).unwrap()),
            )
            .rem(Integer::from(self.n.square_ref())),
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: Integer::from(
                &ciphertext.c * &(((Integer::from(constant) * &self.n) + 1) % &self.n_squared),
            )
            .rem(Integer::from(self.n.square_ref())),
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: Integer::from(
                &ciphertext.c * &(((Integer::from(-constant) * &self.n) + 1) % &self.n_squared),
            )
            .rem(Integer::from(self.n.square_ref())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{
        Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
    };
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(15), &mut rng);

        assert_eq!(15, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(0), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_twice = &ciphertext_a + &ciphertext_b;

        assert_eq!(Integer::from(14), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_sub() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&Integer::from(5), &mut rng);
        let ciphertext_res = &ciphertext_a - &ciphertext_b;

        assert_eq!(Integer::from(2), sk.decrypt(&ciphertext_res));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(9), &mut rng);
        let ciphertext_twice = &ciphertext * &Integer::from(16);

        assert_eq!(144, sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_add_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_res = &ciphertext + &Integer::from(5);

        assert_eq!(Integer::from(12), sk.decrypt(&ciphertext_res));
    }

    #[test]
    fn test_homomorphic_sub_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_res = &ciphertext - &Integer::from(5);

        assert_eq!(Integer::from(2), sk.decrypt(&ciphertext_res));
    }

    #[test]
    fn test_randomize() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt_raw(&Integer::from(21), &mut rng);
        let ciphertext_randomized = pk.randomize(ciphertext.clone(), &mut rng);

        assert_ne!(ciphertext, ciphertext_randomized);

        assert_eq!(
            Integer::from(21),
            sk.decrypt(&ciphertext_randomized.associate(&pk))
        );
    }
}
