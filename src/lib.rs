use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub struct ZKP {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint,
}

impl ZKP {
    pub fn new(p: BigUint, q: BigUint, alpha: BigUint, beta: BigUint) -> Self {
        Self { p, q, alpha, beta }
    }

    /// alpha^x mod p
    /// output: n^exp mod p
    pub fn exponantiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        n.modpow(exponent, modulus)
    }

    /// output: s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        // Gently handle negative modulus problem.
        if *k >= c * x {
            (k - c * x).modpow(&BigUint::from(1u32), &self.q)
        } else {
            &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    /// cond1: r1 = alpha^s * y1^c
    /// cond2: r2 = beta^s * y2^c
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let cond1 = *r1
            == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        let cond2 = *r2
            == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        cond1 && cond2
    }

    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        let mut rng = thread_rng();

        rng.gen_biguint_below(bound)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let zkp = ZKP::new(p, q, alpha, beta);

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        let c = BigUint::from(4u32);

        let y1 = ZKP::exponantiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponantiate(&zkp.beta, &x, &zkp.p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponantiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponantiate(&zkp.beta, &k, &zkp.p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let verification = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(verification);

        // fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);
        let verification = zkp.verify(&r1, &r2, &y1, &y2, &c, &s_fake);
        assert!(!verification);
    }

    #[test]
    fn test_toy_example_with_random_numbers() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP::new(p, q, alpha, beta);

        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_below(&zkp.q);
        let c = ZKP::generate_random_below(&zkp.q);

        let y1 = ZKP::exponantiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponantiate(&zkp.beta, &x, &zkp.p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponantiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponantiate(&zkp.beta, &k, &zkp.p);
        let s = zkp.solve(&k, &c, &x);

        let verification = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(verification);
    }

    fn clear_whitespaces(s: &str) -> String {
        s.to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /*
    Get values from here: https://www.ietf.org/rfc/rfc5114.txt

    p = B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
        DF1FB2BC 2E4A4371

    The hexadecimal value of the generator is:

    g = A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
        855E6EEB 22B3B2E5

    The generator generates a prime-order subgroup of size:

    q = F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353
    */

    #[test]
    fn test_1024_bit_constants() {
        let p = BigUint::from_bytes_be(
            &hex::decode(clear_whitespaces(
                r#"B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
        DF1FB2BC 2E4A4371"#,
            ))
            .unwrap(),
        );

        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
                .expect("Could not decode the hex."),
        );

        let alpha = BigUint::from_bytes_be(
            &hex::decode(clear_whitespaces(
                r#"A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
        855E6EEB 22B3B2E5"#,
            ))
            .unwrap(),
        );

        // beta: alpha^i is also a generator
        let beta = alpha.modpow(&ZKP::generate_random_below(&q), &p);
        let zkp = ZKP::new(p, q, alpha, beta);

        let x = ZKP::generate_random_below(&zkp.q);
        let k = ZKP::generate_random_below(&zkp.q);
        let c = ZKP::generate_random_below(&zkp.q);

        let y1 = ZKP::exponantiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponantiate(&zkp.beta, &x, &zkp.p);
        let r1 = ZKP::exponantiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponantiate(&zkp.beta, &k, &zkp.p);
        let s = zkp.solve(&k, &c, &x);

        let verification = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(verification);
    }
}
