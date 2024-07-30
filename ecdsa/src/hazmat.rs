//! Low-level ECDSA primitives.
//!
//! # ⚠️ Warning: Hazmat!
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces.
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures including
//! FULL PRIVATE KEY RECOVERY!

use crate::{Error, Result};
use core::cmp;
use elliptic_curve::{generic_array::typenum::Unsigned, FieldBytes, PrimeCurve};

// #[cfg(feature = "arithmetic")]
use {
    crate::{RecoveryId, SignatureSize},
    elliptic_curve::{
        ff::{Field, PrimeField},
        group::{Curve as _, Group},
        ops::{Invert, LinearCombination, MulByGenerator, Reduce},
        point::AffineCoordinates,
        scalar::IsHigh,
        subtle::CtOption,
        CurveArithmetic, ProjectivePoint, Scalar,
    },
};

#[cfg(feature = "digest")]
use {
    elliptic_curve::FieldBytesSize,
    signature::{
        digest::{core_api::BlockSizeUser, Digest, FixedOutput, FixedOutputReset},
        PrehashSignature,
    },
};

#[cfg(feature = "rfc6979")]
use elliptic_curve::{FieldBytesEncoding, ScalarPrimitive};

// #[cfg(any(feature = "arithmetic", feature = "digest"))]
use crate::{elliptic_curve::generic_array::ArrayLength, Signature};

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access to the
/// secret scalar via `&self`, such as particular curve's `Scalar` type.
#[cfg(feature = "arithmetic")]
pub trait SignPrimitive<C>:
    AsRef<Self>
    + Into<FieldBytes<C>>
    + IsHigh
    + PrimeField<Repr = FieldBytes<C>>
    + Reduce<C::Uint, Bytes = FieldBytes<C>>
    + Sized
where
    C: PrimeCurve + CurveArithmetic<Scalar = Self>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `k`: ephemeral scalar value. MUST BE UNIFORMLY RANDOM!!!
    /// - `z`: message digest to be signed. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY
    ///        SECURE DIGEST ALGORITHM!!!
    ///
    /// # Returns
    ///
    /// ECDSA [`Signature`] and, when possible/desired, a [`RecoveryId`]
    /// which can be used to recover the verifying key for a given signature.
    fn try_sign_prehashed<K>(
        &self,
        k: K,
        z: &FieldBytes<C>,
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        K: AsRef<Self> + Invert<Output = CtOption<Self>>,
    {
        sign_prehashed(self, k, z).map(|(sig, recid)| (sig, (Some(recid))))
    }

    /// Try to sign the given message digest deterministically using the method
    /// described in [RFC6979] for computing ECDSA ephemeral scalar `k`.
    ///
    /// Accepts the following parameters:
    /// - `z`: message digest to be signed.
    /// - `ad`: optional additional data, e.g. added entropy from an RNG
    ///
    /// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
    #[cfg(feature = "rfc6979")]
    fn try_sign_prehashed_rfc6979<D>(
        &self,
        z: &FieldBytes<C>,
        ad: &[u8],
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        Self: From<ScalarPrimitive<C>> + Invert<Output = CtOption<Self>>,
        D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldBytesSize<C>> + FixedOutputReset,
    {
        let k = Scalar::<C>::from_repr(rfc6979::generate_k::<D, _>(
            &self.to_repr(),
            &C::ORDER.encode_field_bytes(),
            z,
            ad,
        ))
        .unwrap();

        self.try_sign_prehashed::<Self>(k, z)
    }
}

/// Verify the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on type which can access
/// the affine point represeting the public key via `&self`, such as a
/// particular curve's `AffinePoint` type.
#[cfg(feature = "arithmetic")]
pub trait VerifyPrimitive<C>: AffineCoordinates<FieldRepr = FieldBytes<C>> + Copy + Sized
where
    C: PrimeCurve + CurveArithmetic<AffinePoint = Self>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Verify the prehashed message against the provided ECDSA signature.
    ///
    /// Accepts the following arguments:
    ///
    /// - `z`: message digest to be verified. MUST BE OUTPUT OF A
    ///        CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
    /// - `sig`: signature to be verified against the key and message
    fn verify_prehashed(&self, z: &FieldBytes<C>, sig: &Signature<C>) -> Result<()> {
        verify_prehashed(&ProjectivePoint::<C>::from(*self), z, sig)
    }

    /// Verify message digest against the provided signature.
    #[cfg(feature = "digest")]
    fn verify_digest<D>(&self, msg_digest: D, sig: &Signature<C>) -> Result<()>
    where
        D: FixedOutput<OutputSize = FieldBytesSize<C>>,
    {
        self.verify_prehashed(&msg_digest.finalize_fixed(), sig)
    }
}

/// Bind a preferred [`Digest`] algorithm to an elliptic curve type.
///
/// Generally there is a preferred variety of the SHA-2 family used with ECDSA
/// for a particular elliptic curve.
///
/// This trait can be used to specify it, and with it receive a blanket impl of
/// [`PrehashSignature`], used by [`signature_derive`][1]) for the [`Signature`]
/// type for a particular elliptic curve.
///
/// [1]: https://github.com/RustCrypto/traits/tree/master/signature/derive
#[cfg(feature = "digest")]
pub trait DigestPrimitive: PrimeCurve {
    /// Preferred digest to use when computing ECDSA signatures for this
    /// elliptic curve. This is typically a member of the SHA-2 family.
    type Digest: BlockSizeUser
        + Digest
        + FixedOutput<OutputSize = FieldBytesSize<Self>>
        + FixedOutputReset;
}

#[cfg(feature = "digest")]
impl<C> PrehashSignature for Signature<C>
where
    C: DigestPrimitive,
    <FieldBytesSize<C> as core::ops::Add>::Output: ArrayLength<u8>,
{
    type Digest = C::Digest;
}

/// Partial implementation of the `bits2int` function as defined in
/// [RFC6979 § 2.3.2] as well as [SEC1] § 2.3.8.
///
/// This is used to convert a message digest whose size may be smaller or
/// larger than the size of the curve's scalar field into a serialized
/// (unreduced) field element.
///
/// [RFC6979 § 2.3.2]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.2
/// [SEC1]: https://www.secg.org/sec1-v2.pdf
pub fn bits2field<C: PrimeCurve>(bits: &[u8]) -> Result<FieldBytes<C>> {
    // Minimum allowed bits size is half the field size
    if bits.len() < C::FieldBytesSize::USIZE / 2 {
        return Err(Error::new());
    }

    let mut field_bytes = FieldBytes::<C>::default();

    match bits.len().cmp(&C::FieldBytesSize::USIZE) {
        cmp::Ordering::Equal => field_bytes.copy_from_slice(bits),
        cmp::Ordering::Less => {
            // If bits is smaller than the field size, pad with zeroes on the left
            field_bytes[(C::FieldBytesSize::USIZE - bits.len())..].copy_from_slice(bits);
        }
        cmp::Ordering::Greater => {
            // If bits is larger than the field size, truncate
            field_bytes.copy_from_slice(&bits[..C::FieldBytesSize::USIZE]);
        }
    }

    Ok(field_bytes)
}

/// Sign a prehashed message digest using the provided secret scalar and
/// ephemeral scalar, returning an ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `d`: signing key. MUST BE UNIFORMLY RANDOM!!!
/// - `k`: ephemeral scalar value. MUST BE UNIFORMLY RANDOM!!!
/// - `z`: message digest to be signed. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY
///        SECURE DIGEST ALGORITHM!!!
///
/// # Returns
///
/// ECDSA [`Signature`] and, when possible/desired, a [`RecoveryId`]
/// which can be used to recover the verifying key for a given signature.
#[cfg(feature = "arithmetic")]
#[allow(non_snake_case)]
pub fn sign_prehashed<C, K>(
    d: &Scalar<C>,
    k: K,
    z: &FieldBytes<C>,
) -> Result<(Signature<C>, RecoveryId)>
where
    C: PrimeCurve + CurveArithmetic,
    K: AsRef<Scalar<C>> + Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArrayLength<u8>,
{
    // TODO(tarcieri): use `NonZeroScalar<C>` for `k`.
    if k.as_ref().is_zero().into() {
        return Err(Error::new());
    }

    let z = <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(z);

    // Compute scalar inversion of 𝑘
    let k_inv = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

    // Compute 𝑹 = 𝑘×𝑮
    let R = ProjectivePoint::<C>::mul_by_generator(k.as_ref()).to_affine();

    // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
    // integer, then reduce it into an element of the scalar field
    let r = Scalar::<C>::reduce_bytes(&R.x());
    let x_is_reduced = r.to_repr() != R.x();

    // Compute 𝒔 as a signature over 𝒓 and 𝒛.
    let s = k_inv * (z + (r * d));

    // NOTE: `Signature::from_scalars` checks that both `r` and `s` are non-zero.
    let signature = Signature::from_scalars(r, s)?;
    let recovery_id = RecoveryId::new(R.y_is_odd().into(), x_is_reduced);
    Ok((signature, recovery_id))
}

// #[cfg(all(
//     feature = "arithmetic",
//     not(all(target_os = "zkvm", target_vendor = "succinct"))
// ))]
// // #[cfg(all(feature = "arithmetic", target_os = "zkvm", target_vendor = "succinct"))]
// /// Verify the prehashed message against the provided ECDSA signature.
// ///
// /// Accepts the following arguments:
// ///
// /// - `q`: public key with which to verify the signature.
// /// - `z`: message digest to be verified. MUST BE OUTPUT OF A
// ///        CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
// /// - `sig`: signature to be verified against the key and message.
// pub fn verify_prehashed<C>(
//     q: &ProjectivePoint<C>,
//     z: &FieldBytes<C>,
//     sig: &Signature<C>,
// ) -> Result<()>
// where
//     C: PrimeCurve + CurveArithmetic,
//     SignatureSize<C>: ArrayLength<u8>,
// {
//     let z = Scalar::<C>::reduce_bytes(z);
//     let (r, s) = sig.split_scalars();
//     let s_inv = *s.invert_vartime();
//     let u1 = z * s_inv;
//     let u2 = *r * s_inv;
//     let x = ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, q, &u2)
//         .to_affine()
//         .x();

//     if *r == Scalar::<C>::reduce_bytes(&x) {
//         Ok(())
//     } else {
//         Err(Error::new())
//     }
// }
use cfg_if::cfg_if;

fn scalar_to_little_endian_bits<C: PrimeCurve + CurveArithmetic, const NUM_BITS: usize>(
    scalar: &Scalar<C>,
) -> [bool; NUM_BITS]
where
    C: PrimeCurve + CurveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    // Convert the scalar to its byte representation
    let mut bytes = scalar.to_repr();
    bytes.reverse();

    // Create a vector to hold the bits
    let mut bits = [false; NUM_BITS];

    // Iterate over each byte
    for (byte_index, byte) in bytes.iter().enumerate() {
        // Convert each byte to its bits in little endian order
        for bit_index in 0..8 {
            bits[byte_index * 8 + bit_index] = ((byte >> bit_index) & 1) == 1;
        }
    }

    bits
}

// cfg_if! {
//     // if #[cfg(not(all(feature = "arithmetic", target_os = "zkvm", target_vendor = "succinct")))] {
//     if #[cfg(all(feature = "arithmetic", target_os = "zkvm", target_vendor = "succinct"))] {
use sp1_lib::secp256k1::Secp256k1AffinePoint;
use sp1_lib::syscall_secp256k1_decompress;
use sp1_lib::utils::{bytes_to_words_le, AffinePoint};

fn verify_signature<C: PrimeCurve + CurveArithmetic>(
    pubkey: &Secp256k1AffinePoint,
    msg_hash: &[u8; 32],
    signature: &Signature<C>,
    s_inverse: &Scalar<C>,
) -> bool
where
    C: PrimeCurve + CurveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    const GENERATOR: Secp256k1AffinePoint = Secp256k1AffinePoint(Secp256k1AffinePoint::GENERATOR);
    let field = bits2field::<C>(msg_hash);
    if field.is_err() {
        return false;
    }
    let field: Scalar<C> = <C as CurveArithmetic>::Scalar::from_repr(field.unwrap()).unwrap();
    let z = field;
    let (r, s) = signature.split_scalars();

    assert_eq!(*s_inverse * s.as_ref(), <C as CurveArithmetic>::Scalar::ONE);

    let u1 = z * s_inverse;
    let u2 = *r * s_inverse;

    // Convert u1 and u2 to le_bits.
    let u1_le_bits = scalar_to_little_endian_bits::<C, 256>(&u1);
    println!(
        "A bits: {:?}",
        u1_le_bits
            .iter()
            .map(|&b| if b { 1 } else { 0 })
            .collect::<Vec<u8>>()
    );
    let u2_le_bits = scalar_to_little_endian_bits::<C, 256>(&u2);
    println!(
        "B bits: {:?}",
        u2_le_bits
            .iter()
            .map(|&b| if b { 1 } else { 0 })
            .collect::<Vec<u8>>()
    );

    println!("Pubkey affine point: {:?}", pubkey.0);

    let res = Secp256k1AffinePoint::multi_scalar_multiplication(
        &u1_le_bits,
        GENERATOR,
        &u2_le_bits,
        *pubkey,
    )
    .unwrap();

    println!("Result: {:?}", res.0);

    let mut x_bytes_be = [0u8; 32];
    for i in 0..8 {
        x_bytes_be[i * 4..(i * 4) + 4].copy_from_slice(&res.0[i].to_le_bytes());
    }
    x_bytes_be.reverse();

    // let mut x_bytes_be = res.to_le_bytes();
    // x_bytes_be.reverse();
    println!("X bytes: {:?}", x_bytes_be);
    let x_field = bits2field::<C>(&x_bytes_be);
    if x_field.is_err() {
        return false;
    }
    // panic!("Failing HERE");
    *r == <C as CurveArithmetic>::Scalar::from_repr(x_field.unwrap()).unwrap()
}

// CORRECT!
fn decompress_pubkey<C>(q: &ProjectivePoint<C>) -> Secp256k1AffinePoint
where
    C: PrimeCurve + CurveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    let q_affine = q.to_affine();
    let q_affine_x = q_affine.x();
    let is_odd = q_affine.y_is_odd().into();
    let mut decompressed_key = [0u8; 64];
    decompressed_key[..32].copy_from_slice(&q_affine_x);
    unsafe { syscall_secp256k1_decompress(&mut decompressed_key, is_odd) }

    // Reverse decompressed_key
    // decompressed_key.reverse();
    // Convert the now decompressed pubkey into a Secp256k1AffinePoint
    let pubkey_x: Scalar<C> =
        Scalar::from_repr(bits2field::<C>(&decompressed_key[..32]).unwrap()).unwrap();
    let pubkey_y: Scalar<C> =
        Scalar::from_repr(bits2field::<C>(&decompressed_key[32..]).unwrap()).unwrap();
    let mut pubkey_x_le_bytes = pubkey_x.to_repr();
    pubkey_x_le_bytes.reverse();
    let mut pubkey_y_le_bytes = pubkey_y.to_repr();
    pubkey_y_le_bytes.reverse();
    Secp256k1AffinePoint::from_le_bytes(&decompressed_key)
}

/// Verify the prehashed message against the provided ECDSA signature uses the SP1 precompile.
///
/// Accepts the following arguments:
///
/// - `q`: public key with which to verify the signature.
/// - `z`: message digest to be verified. MUST BE OUTPUT OF A
///        CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
/// - `sig`: signature to be verified against the key and message.
pub fn verify_prehashed<C>(
    q: &ProjectivePoint<C>,
    z: &FieldBytes<C>,
    sig: &Signature<C>,
) -> Result<()>
where
    C: PrimeCurve + CurveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    let pubkey = decompress_pubkey::<C>(q);

    // TODO: Use unconstrained ecrecover for inverse.
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();

    let verified = verify_signature::<C>(&pubkey, z.as_slice().try_into().unwrap(), sig, &s_inv);
    if verified {
        Ok(())
    } else {
        Err(Error::new())
    }
}
//     }
// }

#[cfg(test)]
mod tests {
    use super::bits2field;
    use elliptic_curve::dev::MockCurve;
    use hex_literal::hex;

    #[test]
    fn bits2field_too_small() {
        assert!(bits2field::<MockCurve>(b"").is_err());
    }

    #[test]
    fn bits2field_size_less() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(
            field_bytes.as_slice(),
            &hex!("00000000000000000000000000000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    #[test]
    fn bits2field_size_eq() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(field_bytes.as_slice(), &prehash);
    }

    #[test]
    fn bits2field_size_greater() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(
            field_bytes.as_slice(),
            &hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }
}
