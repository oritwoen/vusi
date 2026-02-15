use crate::math::scalar_to_decimal_string;
use crate::signature::SignatureInput;
use anyhow::{Result, bail, anyhow};
use k256::elliptic_curve::ff::{Field, PrimeField};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;
use k256::Scalar;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use num_bigint::BigUint;
use num_traits::Num;

pub struct GeneratorConfig {
    pub weakness: String,
    pub count: usize,
    pub bias_bits: Option<usize>,
    pub seed: Option<u64>,
}

pub fn generate_signatures(config: GeneratorConfig) -> Result<Vec<SignatureInput>> {
    let mut rng = if let Some(seed) = config.seed {
        ChaCha20Rng::seed_from_u64(seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    let priv_key = Scalar::random(&mut rng);
    let pubkey_point = ProjectivePoint::GENERATOR * priv_key;
    let pubkey_hex = hex::encode(pubkey_point.to_affine().to_encoded_point(true).as_bytes());

    let mut signatures = Vec::new();
    let mut last_k: Option<Scalar> = None;

    // LCG parameters (glibc)
    let lcg_a = Scalar::from(1103515245u64);
    let lcg_c = Scalar::from(12345u64);

    for i in 0..config.count {
        let z = Scalar::random(&mut rng);
        let k = match config.weakness.as_str() {
            "reuse" => {
                if i == 0 {
                    Scalar::random(&mut rng)
                } else {
                    last_k.expect("last_k should be set")
                }
            }
            "biased" => {
                let bits = config.bias_bits.unwrap_or(128);
                generate_biased_scalar(&mut rng, bits)
            }
            "lcg" => {
                if let Some(prev) = last_k {
                    prev * lcg_a + lcg_c
                } else {
                    Scalar::random(&mut rng)
                }
            }
            "related" => {
                if let Some(prev) = last_k {
                    prev + Scalar::ONE
                } else {
                    Scalar::random(&mut rng)
                }
            }
            "polynonce" => {
                if let Some(prev) = last_k {
                    prev * prev + Scalar::ONE
                } else {
                    Scalar::random(&mut rng)
                }
            }
            "half-half" => {
                generate_half_half_nonce(&z, &priv_key)
            }
            "none" | "normal" => {
                Scalar::random(&mut rng)
            }
            _ => bail!("Unknown weakness: {}", config.weakness),
        };

        last_k = Some(k);
        let timing = Some(1000 + (k.to_bytes()[0] as u64) * 10); // Simulated timing leak
        let sig = sign_with_k(&priv_key, &k, &z, Some(pubkey_hex.clone()), timing)?;
        signatures.push(sig);
    }

    Ok(signatures)
}

fn sign_with_k(x: &Scalar, k: &Scalar, z: &Scalar, pubkey: Option<String>, timing: Option<u64>) -> Result<SignatureInput> {
    if bool::from(k.is_zero()) {
        bail!("k cannot be zero");
    }

    let r_point = ProjectivePoint::GENERATOR * k;
    let r_affine = r_point.to_affine();
    let r_encoded = r_affine.to_encoded_point(false);
    let x_coord_bytes = r_encoded.x().ok_or_else(|| anyhow!("Failed to get x coordinate"))?;

    let x_coord_bi = BigUint::from_bytes_be(x_coord_bytes);
    let n_bi = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    ).unwrap();

    let r_bi = x_coord_bi % n_bi;
    let mut r_bytes = [0u8; 32];
    let r_bi_bytes = r_bi.to_bytes_be();
    let offset = 32 - r_bi_bytes.len();
    r_bytes[offset..].copy_from_slice(&r_bi_bytes);

    let r = Scalar::from_repr(r_bytes.into()).unwrap();

    if bool::from(r.is_zero()) {
        bail!("r is zero, try another k");
    }

    let k_inv = k.invert().into_option().ok_or_else(|| anyhow!("k has no inverse"))?;
    let s = k_inv * (*z + r * x);

    if bool::from(s.is_zero()) {
        bail!("s is zero, try another k");
    }

    Ok(SignatureInput {
        r: scalar_to_decimal_string(&r),
        s: scalar_to_decimal_string(&s),
        z: scalar_to_decimal_string(z),
        pubkey,
        timing,
    })
}

fn generate_biased_scalar<R: RngCore>(rng: &mut R, bits: usize) -> Scalar {
    let mut bytes = [0u8; 32];
    let bytes_to_fill = (bits + 7) / 8;
    if bytes_to_fill > 32 {
        let mut full_bytes = [0u8; 32];
        rng.fill_bytes(&mut full_bytes);
        return Scalar::from_repr(full_bytes.into()).unwrap_or(Scalar::ZERO);
    }

    let mut small_bytes = vec![0u8; bytes_to_fill];
    rng.fill_bytes(&mut small_bytes);

    if bits % 8 != 0 {
        let mask = (1 << (bits % 8)) - 1;
        if let Some(first) = small_bytes.first_mut() {
            *first &= mask;
        }
    }

    for (i, &b) in small_bytes.iter().rev().enumerate() {
        bytes[31 - i] = b;
    }

    Scalar::from_repr(bytes.into()).unwrap()
}

fn generate_half_half_nonce(z: &Scalar, x: &Scalar) -> Scalar {
    let z_bytes = z.to_bytes();
    let x_bytes = x.to_bytes();

    let mut k_bytes = [0u8; 32];
    k_bytes[..16].copy_from_slice(&z_bytes[..16]);
    k_bytes[16..].copy_from_slice(&x_bytes[..16]);

    Scalar::from_repr(k_bytes.into()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_reuse() {
        let config = GeneratorConfig {
            weakness: "reuse".to_string(),
            count: 2,
            bias_bits: None,
            seed: Some(12345),
        };
        let sigs = generate_signatures(config).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].r, sigs[1].r);
    }
}
