#![warn(missing_docs, unused_imports)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! Number theoretic functions, particularly suited for cryptography. Functions include extremely
//! fast (safe) prime generation.

mod primes;

use rug::integer::IsPrime;
use rug::Integer;
use scicrypt_traits::randomness::SecureRng;
use crate::primes::FIRST_PRIMES;

const REPS: u32 = 25;

/// Generates a uniformly random prime number of a given bit length. So, the number contains
/// `bit_length` bits, of which the first and the last bit are always 1.
pub fn gen_prime<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> Integer {
    'outer: loop {
        let mut candidate = Integer::from(Integer::random_bits(bit_length, &mut rng.rug_rng()));

        let set_bits = (Integer::from(1) << (bit_length - 1)) + Integer::from(1);
        candidate |= set_bits;

        // From OpenSSL (https://github.com/openssl/openssl/blob/4cedf30e995f9789cf6bb103e248d33285a84067/crypto/bn/bn_prime.c)
        let prime_count = match bit_length {
            0..=512 => 64,
            513..=1024 => 128,
            1025..=2048 => 384,
            2049..=4096 => 1024,
            _ => 2048,
        };
        let mods: Vec<u32> = FIRST_PRIMES[..prime_count].iter().map(|p| candidate.mod_u(*p)).collect();

        let mut delta = 0;
        let max_delta = u32::MAX - FIRST_PRIMES.last().unwrap();
        candidate = 'sieve: loop {
            for i in 1..prime_count {
                if (mods[i] + delta) % FIRST_PRIMES[i] == 0 {
                    // For candidate x and prime p, if x % p = 0 then x is not prime
                    // So, we go to the next odd number and try again
                    delta += 2;

                    if delta > max_delta {
                        continue 'outer;
                    }

                    continue 'sieve;
                }
            }

            // If we have passed all prime_count first primes, then we are fairly certain this is a prime!
            break candidate + delta;
        };

        // Ensure that we have a prime with a stronger primality test
        if candidate.is_probably_prime(REPS) != IsPrime::No {
            return candidate;
        }
    }
}

/// Generates a uniformly random *safe* prime number of a given bit length. This is a prime $p$ of
/// the form $p = 2q + 1$, where $q$ is a smaller prime.
pub fn gen_safe_prime<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> Integer {
    'outer: loop {
        let mut candidate = Integer::from(Integer::random_bits(bit_length, &mut rng.rug_rng()));

        let set_bits = (Integer::from(1) << (bit_length - 1)) + Integer::from(1);
        candidate |= set_bits;

        // From OpenSSL (https://github.com/openssl/openssl/blob/4cedf30e995f9789cf6bb103e248d33285a84067/crypto/bn/bn_prime.c)
        let prime_count = match bit_length {
            0..=512 => 64,
            513..=1024 => 128,
            1025..=2048 => 384,
            2049..=4096 => 1024,
            _ => 2048,
        };
        let mods: Vec<u32> = FIRST_PRIMES[..prime_count].iter().map(|p| candidate.mod_u(*p)).collect();

        let mut delta = 0;
        let max_delta = u32::MAX - FIRST_PRIMES.last().unwrap();
        candidate = 'sieve: loop {
            for i in 1..prime_count {
                if (mods[i] + delta) % FIRST_PRIMES[i] <= 1 {
                    // For candidate x and prime p, if x % p = 0 then x is not prime
                    // So, we go to the next odd number and try again
                    delta += 4;

                    if delta > max_delta {
                        continue 'outer;
                    }

                    continue 'sieve;
                }
            }

            // If we have passed all prime_count first primes, then we are fairly certain this is a prime!
            break candidate + delta;
        };

        // Ensure that we have a prime with a stronger primality test
        if candidate.is_probably_prime(REPS) != IsPrime::No {
            // Ensure that p for 2p = 1 is also a prime with the stronger primality test
            let candidate_reduced = Integer::from(&candidate >> 1);
            if candidate_reduced.is_probably_prime(REPS) != IsPrime::No {
                return candidate;
            }
        }
    }
}

/// Generates a uniformly random RSA modulus, which is the product of two safe primes $p$ and $q$.
/// This method returns both the modulus and $\lambda$, which is the least common multiple of
/// $p - 1$ and $q - 1$.
pub fn gen_rsa_modulus<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> (Integer, Integer) {
    let p = gen_safe_prime(bit_length / 2, rng);
    let q = gen_safe_prime(bit_length / 2, rng);

    let n = Integer::from(&p * &q);

    let lambda: Integer = (p - Integer::from(1)).lcm(&(q - Integer::from(1)));

    (n, lambda)
}

/// Generates a uniformly random coprime $x$ to the `other` integer $y$. This means that
/// $\gcd(x, y) = 1$.
pub fn gen_coprime<R: rand_core::RngCore + rand_core::CryptoRng>(
    other: &Integer,
    rng: &mut SecureRng<R>,
) -> Integer {
    loop {
        let candidate = Integer::from(other.random_below_ref(&mut rng.rug_rng()));

        if Integer::from(candidate.gcd_ref(other)) == 1 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{gen_prime, gen_safe_prime};
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::randomness::SecureRng;

    fn assert_primality_100_000_factors(integer: &Integer) {
        let (_, hi) = primal::estimate_nth_prime(100_000);
        for prime in primal::Sieve::new(hi as usize).primes_from(0) {
            assert!(
                !integer.is_divisible_u(prime as u32),
                "{} is divisible by {}",
                integer,
                prime
            );
        }
    }

    #[test]
    fn test_gen_prime_for_factors() {
        let mut rng = SecureRng::new(OsRng);
        let generated_prime = gen_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);
    }

    #[test]
    fn test_gen_safe_prime_for_factors() {
        let mut rng = SecureRng::new(OsRng);
        let generated_prime = gen_safe_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);

        let sophie_germain_prime = generated_prime >> 1;

        assert_primality_100_000_factors(&sophie_germain_prime);
    }
}
