//! Public key recovery support.

use crate::{Error, Result};

#[cfg(feature = "signing")]
use {
    crate::{hazmat::SignPrimitive, SigningKey},
    elliptic_curve::subtle::CtOption,
    signature::{hazmat::PrehashSigner, DigestSigner, Signer},
};

#[cfg(feature = "verifying")]
use {
    crate::{hazmat::VerifyPrimitive, VerifyingKey},
    elliptic_curve::{
        bigint::CheckedAdd,
        ops::{LinearCombination, Reduce},
        point::DecompressPoint,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, FieldBytesEncoding, FieldBytesSize, Group, PrimeField, ProjectivePoint,
    },
    signature::hazmat::PrehashVerifier,
};

#[cfg(any(feature = "signing", feature = "verifying"))]
use {
    crate::{
        hazmat::{bits2field, DigestPrimitive},
        Signature, SignatureSize,
    },
    elliptic_curve::{
        ff::Field, generic_array::ArrayLength, ops::Invert, CurveArithmetic, NonZeroScalar,
        PrimeCurve, Scalar,
    },
    signature::digest::Digest,
};

//#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
use {
    digest::generic_array::GenericArray,
    elliptic_curve::{
        bigint::{
            modular::runtime_mod::{DynResidue, DynResidueParams},
            ArrayEncoding, Encoding, U256,
        },
        sec1::EncodedPoint,
        Curve,
    },
    sp1_lib::{
        secp256k1::Secp256k1Point, secp256r1::Secp256r1Point, utils::AffinePoint as Sp1AffinePoint,
        utils::WeierstrassAffinePoint,
    },
};

/// Recovery IDs, a.k.a. "recid".
///
/// This is an integer value `0`, `1`, `2`, or `3` included along with a
/// signature which is used during the recovery process to select the correct
/// public key from the signature.
///
/// It consists of two bits of information:
///
/// - low bit (0/1): was the y-coordinate of the affine point resulting from
///   the fixed-base multiplication 𝑘×𝑮 odd? This part of the algorithm
///   functions similar to point decompression.
/// - hi bit (3/4): did the affine x-coordinate of 𝑘×𝑮 overflow the order of
///   the scalar field, requiring a reduction when computing `r`?
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RecoveryId(u8);

impl RecoveryId {
    /// Maximum supported value for the recovery ID (inclusive).
    pub const MAX: u8 = 3;

    /// Create a new [`RecoveryId`] from the following 1-bit arguments:
    ///
    /// - `is_y_odd`: is the affine y-coordinate of 𝑘×𝑮 odd?
    /// - `is_x_reduced`: did the affine x-coordinate of 𝑘×𝑮 overflow the curve order?
    pub const fn new(is_y_odd: bool, is_x_reduced: bool) -> Self {
        Self((is_x_reduced as u8) << 1 | (is_y_odd as u8))
    }

    /// Did the affine x-coordinate of 𝑘×𝑮 overflow the curve order?
    pub const fn is_x_reduced(self) -> bool {
        (self.0 & 0b10) != 0
    }

    /// Is the affine y-coordinate of 𝑘×𝑮 odd?
    pub const fn is_y_odd(self) -> bool {
        (self.0 & 1) != 0
    }

    /// Convert a `u8` into a [`RecoveryId`].
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte <= Self::MAX {
            Some(Self(byte))
        } else {
            None
        }
    }

    /// Convert this [`RecoveryId`] into a `u8`.
    pub const fn to_byte(self) -> u8 {
        self.0
    }
}

#[cfg(feature = "verifying")]
impl RecoveryId {
    /// Given a public key, message, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_msg<C>(
        verifying_key: &VerifyingKey<C>,
        msg: &[u8],
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: DigestPrimitive + PrimeCurve + CurveArithmetic,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        SignatureSize<C>: ArrayLength<u8>,
    {
        Self::trial_recovery_from_digest(verifying_key, C::Digest::new_with_prefix(msg), signature)
    }

    /// Given a public key, message digest, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_digest<C, D>(
        verifying_key: &VerifyingKey<C>,
        digest: D,
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: PrimeCurve + CurveArithmetic,
        D: Digest,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        SignatureSize<C>: ArrayLength<u8>,
    {
        Self::trial_recovery_from_prehash(verifying_key, &digest.finalize(), signature)
    }

    /// Given a public key, message digest, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_prehash<C>(
        verifying_key: &VerifyingKey<C>,
        prehash: &[u8],
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: PrimeCurve + CurveArithmetic,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        SignatureSize<C>: ArrayLength<u8>,
    {
        for id in 0..=Self::MAX {
            let recovery_id = RecoveryId(id);

            if let Ok(vk) = VerifyingKey::recover_from_prehash(prehash, signature, recovery_id) {
                if verifying_key == &vk {
                    return Ok(recovery_id);
                }
            }
        }

        Err(Error::new())
    }
}

impl TryFrom<u8> for RecoveryId {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self> {
        Self::from_byte(byte).ok_or_else(Error::new)
    }
}

impl From<RecoveryId> for u8 {
    fn from(id: RecoveryId) -> u8 {
        id.0
    }
}

#[cfg(feature = "signing")]
impl<C> SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign the given message prehash, returning a signature and recovery ID.
    pub fn sign_prehash_recoverable(&self, prehash: &[u8]) -> Result<(Signature<C>, RecoveryId)> {
        let z = bits2field::<C>(prehash)?;
        let (sig, recid) = self
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<C::Digest>(&z, &[])?;

        Ok((sig, recid.ok_or_else(Error::new)?))
    }

    /// Sign the given message digest, returning a signature and recovery ID.
    pub fn sign_digest_recoverable<D>(&self, msg_digest: D) -> Result<(Signature<C>, RecoveryId)>
    where
        D: Digest,
    {
        self.sign_prehash_recoverable(&msg_digest.finalize())
    }

    /// Sign the given message, hashing it with the curve's default digest
    /// function, and returning a signature and recovery ID.
    pub fn sign_recoverable(&self, msg: &[u8]) -> Result<(Signature<C>, RecoveryId)> {
        self.sign_digest_recoverable(C::Digest::new_with_prefix(msg))
    }
}

#[cfg(feature = "signing")]
impl<C, D> DigestSigner<D, (Signature<C>, RecoveryId)> for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign_digest(&self, msg_digest: D) -> Result<(Signature<C>, RecoveryId)> {
        self.sign_digest_recoverable(msg_digest)
    }
}

#[cfg(feature = "signing")]
impl<C> PrehashSigner<(Signature<C>, RecoveryId)> for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn sign_prehash(&self, prehash: &[u8]) -> Result<(Signature<C>, RecoveryId)> {
        self.sign_prehash_recoverable(prehash)
    }
}

#[cfg(feature = "signing")]
impl<C> Signer<(Signature<C>, RecoveryId)> for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<(Signature<C>, RecoveryId)> {
        self.sign_recoverable(msg)
    }
}

#[cfg(feature = "verifying")]
impl<C> VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Recover a [`VerifyingKey`] from the given message, signature, and
    /// [`RecoveryId`].
    ///
    /// The message is first hashed using this curve's [`DigestPrimitive`].
    pub fn recover_from_msg(
        msg: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self>
    where
        C: DigestPrimitive,
    {
        Self::recover_from_digest(C::Digest::new_with_prefix(msg), signature, recovery_id)
    }

    /// Recover a [`VerifyingKey`] from the given message [`Digest`],
    /// signature, and [`RecoveryId`].
    pub fn recover_from_digest<D>(
        msg_digest: D,
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self>
    where
        D: Digest,
    {
        Self::recover_from_prehash(&msg_digest.finalize(), signature, recovery_id)
    }

    /// Recover a [`VerifyingKey`] from the given `prehash` of a message, the
    /// signature over that prehashed message, and a [`RecoveryId`].
    ///
    /// This function has been modified to support SP1 acceleration for secp256k1 signature verification
    /// in the context of a zkVM. If the curve is secp256k1 and the prehash is 32 bytes long (indicating a SHA-256 hash),
    /// the function will use [`crate::sp1::VerifyingKey::recover_from_prehash_secp256k1`] to return a precomputed public key.
    #[allow(non_snake_case)]
    pub fn recover_from_prehash(
        prehash: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self> {
        // `split_scalars` checks that `r`, `s` are non-zero and within scalar range.
        // `ScalarPrimitive` is guaranteed to be canonical, and `NonZeroScalar` checks value is non-zero.
        let (r, s) = signature.split_scalars();
        let z = <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&bits2field::<C>(prehash)?);

        let mut r_bytes = r.to_repr();
        if recovery_id.is_x_reduced() {
            match Option::<C::Uint>::from(
                C::Uint::decode_field_bytes(&r_bytes).checked_add(&C::ORDER),
            ) {
                Some(restored) => r_bytes = restored.encode_field_bytes(),
                // No reduction should happen here if r was reduced
                None => return Err(Error::new()),
            };
        }

        #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
        return Self::recover_from_prehash_zkvm(
            r,
            r_bytes.as_slice().try_into().unwrap(),
            recovery_id.is_y_odd(),
            s,
            z,
        );

        let R = AffinePoint::<C>::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());

        if R.is_none().into() {
            return Err(Error::new());
        }

        let R = ProjectivePoint::<C>::from(R.unwrap());
        let r_inv = *r.invert();
        let u1 = -(r_inv * z);
        let u2 = r_inv * *s;
        let pk = ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, &R, &u2);
        let vk = Self::from_affine(pk.into())?;

        // Ensure signature verifies with the recovered key
        vk.verify_prehash(prehash, signature)?;

        Ok(vk)
    }

    /// Compute the public key from the the signature scalars and prehash.
    ///
    /// Note: This function is optimized to be used inside the SP1 zkVM.
    /// We offload the scalar multiplication and certian field ops (invert, sqrt) to the host,
    /// to be hinted back to the vm, which can then be constrained to be accurate.
    #[allow(warnings)]
    //#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
    fn recover_from_prehash_zkvm(
        r: NonZeroScalar<C>,
        R_x_bytes: [u8; 32],
        R_y_odd: bool,
        s: NonZeroScalar<C>,
        z: <C as CurveArithmetic>::Scalar,
    ) -> Result<Self> {
        let (a, b, nqr, base_field_params, curve_id) = ec_params_256_bit::<C>();

        // If the `R_x` value is not canonical, return failure.
        let R_x = U256::from_be_slice(&R_x_bytes);
        if &R_x >= base_field_params.modulus() {
            return Err(Error::new());
        }

        let R_x = DynResidue::new(&R_x, base_field_params);
        // The first step of the recovery is to decompress the R point, whose x-coordinate is given
        // by r_x_bytes.
        let alpha = R_x * R_x * R_x + (a * R_x) + b;

        // The hook expects the highbit to encode `r_y_is_odd` and the low bits to be curve id.
        //
        // The hook should return the inverse of r in the scalar field, which is used to compute u1 and u2.
        //
        // If recovering R fails, the hook should return a status code, that lets us constrain this
        // failure. The only way this fails if alpha is a NQR.
        let mut buf = [0u8; 65];
        buf[0] = curve_id | u8::from(R_y_odd) << 7;
        buf[1..33].copy_from_slice(r.to_repr().as_slice());
        buf[33..65].copy_from_slice(&alpha.retrieve().to_be_bytes());

        // todo: change the name of this hook
        sp1_lib::io::write(sp1_lib::io::FD_ECRECOVER_HOOK, &buf);

        let status: bool = sp1_lib::io::read();
        if !status {
            // The status indicates that the recovery failed.
            // So we need to constrain the by proving alpha is non square in the base field.
            let root_bytes = sp1_lib::io::read_vec();
            let root = DynResidue::new(&U256::from_be_slice(&root_bytes), base_field_params);

            assert!(root * root == alpha * nqr, "Invalid hint for status");

            return Err(Error::new());
        }

        // The point R in the form [x || y] where x and y are 32 bytes each, big endian.
        let R_y_bytes = sp1_lib::io::read_vec();
        let R_y = U256::from_be_slice(&R_y_bytes);

        // `R_y` hint should be in canonical form.
        assert!(
            &R_y < base_field_params.modulus(),
            "hint should return canonical value"
        );

        let R_y = DynResidue::new(&R_y, base_field_params);

        // The y-coordinate must be the sqrt of alpha
        assert!(R_y * R_y == alpha, "Invalid hint for R_y");

        // Check the lowest bit (corresponding to the 2^0 place), constraining the point by the recovery id.
        assert_eq!(
            R_y.retrieve().to_be_bytes().as_slice()[31] & 1 == 1,
            R_y_odd,
            "Invalid hint for R_y_odd"
        );

        // This should be the big endian representation of the inverse of r mod n.
        let r_inv_bytes = sp1_lib::io::read_vec();

        // Ensure the r_inv is correct and canon.
        //
        // Here r_inv is modulo the scalar field.
        let r_inv = C::Scalar::reduce_bytes(GenericArray::from_slice(&r_inv_bytes));
        assert!(
            r_inv * *r == <C::Scalar as Field>::ONE,
            "Invalid hint for r_inv"
        );

        let u1 = -(r_inv * z);
        let u2 = r_inv * *s;

        let (u1_bytes, u2_bytes) = (u1.to_repr(), u2.to_repr());

        let u1_le_bits = be_bytes_to_le_bits(u1_bytes.as_slice().try_into().unwrap());
        let u2_le_bits = be_bytes_to_le_bits(u2_bytes.as_slice().try_into().unwrap());
        let R_point_bytes: [u8; 64] = {
            let mut R_point_bytes = [0u8; 64];

            let mut R_x_bytes = R_x_bytes;
            R_x_bytes.reverse();

            let mut R_y_bytes = R_y_bytes;
            R_y_bytes.reverse();

            R_point_bytes[0..32].copy_from_slice(&R_x_bytes);
            R_point_bytes[32..64].copy_from_slice(&R_y_bytes);
            R_point_bytes
        };

        let mut pk_le_bytes: [u8; 64] = match curve_id {
            // secp256k1
            1 => {
                let p = Secp256k1Point::multi_scalar_multiplication(
                    &u1_le_bits,
                    Secp256k1Point::new(Secp256k1Point::GENERATOR),
                    &u2_le_bits,
                    Secp256k1Point::from_le_bytes(&R_point_bytes),
                );

                // Return error for result being the point at infinity.
                if p.is_infinity() {
                    return Err(Error::new());
                }

                p.to_le_bytes()
                    .try_into()
                    .expect("a valid point should have 64 bytes")
            }
            2 => {
                let p = Secp256r1Point::multi_scalar_multiplication(
                    &u1_le_bits,
                    Secp256r1Point::new(Secp256r1Point::GENERATOR),
                    &u2_le_bits,
                    Secp256r1Point::from_le_bytes(&R_point_bytes),
                );

                // Return error for result being the point at infinity.
                if p.is_infinity() {
                    return Err(Error::new());
                }

                p.to_le_bytes()
                    .try_into()
                    .expect("a valid point should have 64 bytes")
            }
            _ => unimplemented!(),
        };

        // Convert the point to big endian.
        let pk_bytes = {
            let (x, y) = pk_le_bytes.split_at_mut(32);

            x.reverse();
            y.reverse();

            let mut be_bytes = [0u8; 64];
            be_bytes[0..32].copy_from_slice(&x);
            be_bytes[32..].copy_from_slice(&y);

            be_bytes
        };

        let encoded_point =
            EncodedPoint::<C>::from_untagged_bytes(GenericArray::from_slice(&pk_bytes));

        let affine = AffinePoint::<C>::from_encoded_point(&encoded_point)
            .into_option()
            .unwrap();

        Ok(Self::from_affine(affine)?)
    }
}

/// Convert big-endian bytes with the most significant bit first to little-endian bytes with the least significant bit first.
#[inline]
//#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
fn be_bytes_to_le_bits(be_bytes: &[u8; 32]) -> [bool; 256] {
    let mut bits = [false; 256];
    // Reverse the byte order to little-endian.
    for (i, &byte) in be_bytes.iter().rev().enumerate() {
        for j in 0..8 {
            // Flip the bit order so the least significant bit is now the first bit of the chunk.
            bits[i * 8 + j] = ((byte >> j) & 1) == 1;
        }
    }
    bits
}

#[cfg(target_os = "zkvm")]
type ECParams = (
    DynResidue<8>,
    DynResidue<8>,
    DynResidue<8>,
    DynResidueParams<8>,
    u8,
);

#[cfg(not(target_os = "zkvm"))]
type ECParams = (
    DynResidue<4>,
    DynResidue<4>,
    DynResidue<4>,
    DynResidueParams<4>,
    u8,
);

#[inline]
//#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
fn ec_params_256_bit<C: Curve>() -> ECParams {
    // 3 is the non-quadratic residue of the base field of secp256k1 and secp256r1.
    const NQR: [u8; 32] = {
        let mut nqr = [0; 32];
        nqr[31] = 3;
        nqr
    };

    // Reference: https://en.bitcoin.it/wiki/Secp256k1.
    // This is the order of the elliptic curve group.
    const SECP256K1_ORDER: [u8; 32] =
        hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    const SECP256K1_BASE_FIELD_ORDER: [u8; 32] =
        hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    // SECP256K1_A
    const SECP256K1_A: [u8; 32] = [0; 32];
    // SECP256K1_B
    const SECP256K1_B: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 7;
        b
    };

    // Reference: https://neuromancer.sk/std/secg/secp256r1.
    // This is the order of the elliptic curve group.
    const SECP256R1_ORDER: [u8; 32] =
        hex_literal::hex!("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    const SECP256R1_BASE_FIELD_ORDER: [u8; 32] =
        hex_literal::hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    // SECP256R1_A
    const SECP256R1_A: [u8; 32] =
        hex_literal::hex!("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    // SECP256R1_B
    const SECP256R1_B: [u8; 32] =
        hex_literal::hex!("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    let a;
    let b;
    let base_field_params;
    let curve_id;

    if C::ORDER.to_be_byte_array().as_slice() == SECP256K1_ORDER.as_slice() {
        base_field_params = DynResidueParams::new(&U256::from_be_bytes(SECP256K1_BASE_FIELD_ORDER));

        a = DynResidue::new(&U256::from_be_bytes(SECP256K1_A), base_field_params);
        b = DynResidue::new(&U256::from_be_bytes(SECP256K1_B), base_field_params);
        curve_id = 1;
    } else if C::ORDER.to_be_byte_array().as_slice() == SECP256R1_ORDER.as_slice() {
        base_field_params = DynResidueParams::new(&U256::from_be_bytes(SECP256R1_BASE_FIELD_ORDER));

        a = DynResidue::new(&U256::from_be_bytes(SECP256R1_A), base_field_params);
        b = DynResidue::new(&U256::from_be_bytes(SECP256R1_B), base_field_params);
        curve_id = 2;
    } else {
        unimplemented!("Unsupported curve");
    };

    (
        a,
        b,
        DynResidue::new(&U256::from_be_bytes(NQR), base_field_params),
        base_field_params,
        curve_id,
    )
}

#[cfg(test)]
mod tests {
    use super::RecoveryId;

    #[test]
    fn new() {
        assert_eq!(RecoveryId::new(false, false).to_byte(), 0);
        assert_eq!(RecoveryId::new(true, false).to_byte(), 1);
        assert_eq!(RecoveryId::new(false, true).to_byte(), 2);
        assert_eq!(RecoveryId::new(true, true).to_byte(), 3);
    }

    #[test]
    fn try_from() {
        for n in 0u8..=3 {
            assert_eq!(RecoveryId::try_from(n).unwrap().to_byte(), n);
        }

        for n in 4u8..=255 {
            assert!(RecoveryId::try_from(n).is_err());
        }
    }

    #[test]
    fn is_x_reduced() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_x_reduced(), true);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_x_reduced(), true);
    }

    #[test]
    fn is_y_odd() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_y_odd(), true);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_y_odd(), true);
    }
}
