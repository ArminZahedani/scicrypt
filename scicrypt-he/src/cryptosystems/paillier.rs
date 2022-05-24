use rug::Integer;
use scicrypt_numbertheory::{gen_coprime, gen_rsa_modulus};
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::cryptosystems::EncryptRaw;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::Enrichable;
use std::ops::{Add, Mul, Rem};
use serde::{Serialize, Deserialize};

/// The Paillier cryptosystem.
pub struct Paillier;

/// Public key for the Paillier cryptosystem.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PaillierPublicKey {
    /// Public modulus n
    pub n: Integer,

    /// Public group g
    pub g: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Hash)]
pub struct PaillierCiphertext {
    /// Raw Ciphertext in Integer form
    pub c: Integer,
}

/// A struct holding both a ciphertext and a reference to its associated public key, which is
/// useful for decrypting directly using the secret key or performing homomorphic operations.
#[derive(Clone)]
pub struct RichPaillierCiphertext<'pk> {
    /// The ciphertext to operate on
    pub ciphertext: PaillierCiphertext,
    /// Reference to the associated public key
    public_key: &'pk PaillierPublicKey,
}

impl<'pk> Enrichable<'pk, PaillierPublicKey, RichPaillierCiphertext<'pk>> for PaillierCiphertext {
    fn enrich(self, public_key: &PaillierPublicKey) -> RichPaillierCiphertext
    where
        Self: Sized,
    {
        RichPaillierCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl AsymmetricCryptosystem<'_> for Paillier {
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;
    type RichCiphertext<'pk> = RichPaillierCiphertext<'pk>;

    type PublicKey = PaillierPublicKey;
    type SecretKey = (Integer, Integer);

    /// Generates a fresh Paillier keypair.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// let mut rng = GeneralRng::new(OsRng);
    /// let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// ```
    fn generate_keys<R: SecureRng>(
        security_param: &BitsOfSecurity,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let (n, lambda) = gen_rsa_modulus(security_param.to_public_key_bit_length(), rng);

        let g = &n + Integer::from(1);
        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        (PaillierPublicKey { n, g }, (lambda, mu))
    }

    /// Encrypts a plaintext integer using the Paillier public key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// let ciphertext = Paillier::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// ```
    fn encrypt<R: SecureRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.n.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(public_key.g.pow_mod_ref(plaintext, &n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.n, &n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }

    /// Decrypts a rich Paillier ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt_traits::Enrichable;
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// # let ciphertext = Paillier::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// let rich_ciphertext = ciphertext.enrich(&public_key);
    /// println!("The decrypted message is {}", Paillier::decrypt(&rich_ciphertext, &secret_key));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt(
        rich_ciphertext: &RichPaillierCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext {
        let (lambda, mu) = secret_key;
        let n_squared = Integer::from(rich_ciphertext.public_key.n.square_ref());

        let mut inner = Integer::from(
            rich_ciphertext
                .ciphertext
                .c
                .secure_pow_mod_ref(lambda, &n_squared),
        );
        inner -= 1;
        inner /= &rich_ciphertext.public_key.n;
        inner *= mu;

        inner.rem(&rich_ciphertext.public_key.n)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'pk> Add for &RichPaillierCiphertext<'pk> {
    type Output = RichPaillierCiphertext<'pk>;

    fn add(self, rhs: Self) -> Self::Output {
        RichPaillierCiphertext {
            ciphertext: PaillierCiphertext {
                c: Integer::from(&self.ciphertext.c * &rhs.ciphertext.c)
                    .rem(Integer::from(self.public_key.n.square_ref())),
            },
            public_key: self.public_key,
        }
    }
}
impl EncryptRaw<'_> for Paillier {
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;
    type RichCiphertext<'pk> = RichPaillierCiphertext<'pk>;

    type PublicKey = PaillierPublicKey;
    type SecretKey = (Integer, Integer);

    fn encrypt_raw(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        r: Integer,
    ) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.n.square_ref());
        //let r = Integer::from(*r);

        let first = Integer::from(public_key.g.pow_mod_ref(plaintext, &n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.n, &n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }
}

impl<'pk> Mul<&Integer> for &RichPaillierCiphertext<'pk> {
    type Output = RichPaillierCiphertext<'pk>;

    fn mul(self, rhs: &Integer) -> Self::Output {
        let modulus = Integer::from(self.public_key.n.square_ref());

        RichPaillierCiphertext {
            ciphertext: PaillierCiphertext {
                c: Integer::from(self.ciphertext.c.pow_mod_ref(rhs, &modulus).unwrap()),
            },
            public_key: self.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::Enrichable;
    use crate::cryptosystems::paillier::PaillierCiphertext;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(15), &pk, &mut rng);

        assert_eq!(
            Integer::from(15),
            Paillier::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(7), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(Integer::from(14), Paillier::decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(9), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext * &Integer::from(16);

        assert_eq!(
            Integer::from(144),
            Paillier::decrypt(&ciphertext_twice, &sk)
        );
    }
    #[test]
    fn test_homomorphic_subtract() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(10), &pk, &mut rng).enrich(&pk);
        let ciphertext2 = Paillier::encrypt(&Integer::from(3), &pk, &mut rng).enrich(&pk);

        let n_squared = Integer::from(pk.n.square_ref());
        let invert = PaillierCiphertext {c: ciphertext2.ciphertext.c.invert(&n_squared).unwrap()};
        let ciphertext_subtract = &ciphertext + &invert.enrich(&pk);

        assert_eq!(
            Integer::from(7),
            Paillier::decrypt(&ciphertext_subtract, &sk)
        );
    }
}
