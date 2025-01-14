//! ECDSA verifying: checking signatures are authentic using a [`VerifyingKey`].
//!
//! # ⚠️ Warning: our patching can cause issues for users who want to use VerifyingKey on curves that don't
//!  implement the traits:
//!     AffinePoint<C>:
//!     DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
//!     FieldBytesSize<C>: sec1::ModulusSize,

use crate::RecoveryId;
use crate::{
    hazmat::{bits2field, DigestPrimitive, VerifyPrimitive},
    Error, Result, Signature, SignatureSize,
};
use core::{cmp::Ordering, fmt::Debug};
use elliptic_curve::{
    generic_array::ArrayLength,
    point::{DecompressPoint, PointCompression},
    sec1::{self, CompressedPoint, EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesEncoding, FieldBytesSize, PrimeCurve, PublicKey,
};
use signature::{
    digest::{Digest, FixedOutput},
    hazmat::PrehashVerifier,
    DigestVerifier, Verifier,
};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "der")]
use {crate::der, core::ops::Add};

#[cfg(feature = "pem")]
use {
    core::str::FromStr,
    elliptic_curve::pkcs8::{DecodePublicKey, EncodePublicKey},
};

#[cfg(feature = "pkcs8")]
use elliptic_curve::pkcs8::{
    self,
    der::AnyRef,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier},
    AssociatedOid, ObjectIdentifier,
};

#[cfg(feature = "sha2")]
use {
    crate::{
        SignatureWithOid, ECDSA_SHA224_OID, ECDSA_SHA256_OID, ECDSA_SHA384_OID, ECDSA_SHA512_OID,
    },
    sha2::{Sha224, Sha256, Sha384, Sha512},
};

#[cfg(all(feature = "pem", feature = "serde"))]
use serdect::serde::{de, ser, Deserialize, Serialize};

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
        use crate::ec_params_256_bit;
        use digest::generic_array::GenericArray;
        use elliptic_curve::Curve;
    }
}

/// ECDSA public key used for verifying signatures. Generic over prime order
/// elliptic curves (e.g. NIST P-curves)
///
/// Requires an [`elliptic_curve::CurveArithmetic`] impl on the curve, and a
/// [`VerifyPrimitive`] impl on its associated `AffinePoint` type.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for verifying:
///
/// - [`Verifier`]: verify a message against a provided key and signature
/// - [`DigestVerifier`]: verify a message [`Digest`] against a provided key and signature
/// - [`PrehashVerifier`]: verify the low-level raw output bytes of a message digest
///
/// See the [`p256` crate](https://docs.rs/p256/latest/p256/ecdsa/index.html)
/// for examples of using this type with a concrete elliptic curve.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, it provides support for
/// serializing and deserializing ECDSA signatures using the `Serialize` and
/// `Deserialize` traits.
///
/// The serialization leverages the encoding used by the [`PublicKey`] type,
/// which is a binary-oriented ASN.1 DER encoding.
#[derive(Clone, Debug)]
pub struct VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    pub(crate) inner: PublicKey<C>,
}

impl<C> VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        PublicKey::from_sec1_bytes(bytes)
            .map(|pk| Self { inner: pk })
            .map_err(|_| Error::new())
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint<C>) -> Result<Self> {
        Ok(Self {
            inner: PublicKey::from_affine(affine).map_err(|_| Error::new())?,
        })
    }

    /// Initialize [`VerifyingKey`] from an [`EncodedPoint`].
    pub fn from_encoded_point(public_key: &EncodedPoint<C>) -> Result<Self> {
        Option::from(PublicKey::<C>::from_encoded_point(public_key))
            .map(|public_key| Self { inner: public_key })
            .ok_or_else(Error::new)
    }

    /// Serialize this [`VerifyingKey`] as a SEC1 [`EncodedPoint`], optionally
    /// applying point compression.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.inner.to_encoded_point(compress)
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]>
    where
        C: PointCompression,
    {
        self.inner.to_sec1_bytes()
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint<C> {
        self.inner.as_affine()
    }

    /// Verify the prehashed message against the provided ECDSA signature using SP1 acceleration.
    /// (essentially the same as verify_signature_secp256, but only takes in signature and finds inverse of s)
    /// Accepts the following arguments:
    /// - `pubkey`: The public key to verify the signature against. The public key is in uncompressed form. The points
    /// are represented as big-endian bytes and need to be converted to little endian to instantiate the Secp256k1Point.
    /// - `msg_hash`: The prehashed message to verify the signature against.
    /// - `signature`: The signature to verify.
    /// - `ec_params`: The elliptic curve parameters.
    #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
    pub fn verify_prehash_secp256(
        pubkey: &[u8; 65],
        prehash: &[u8],
        signature: &Signature<C>,
        ec_params: ECParams,
    ) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature.to_bytes());
        let s_inv = recover_s_inv_unconstrained(&sig_bytes);

        // Convert the s_inverse bytes to a scalar.
        let s_inverse = Scalar::<C>::from_repr(bits2field::<C>(&s_inv).unwrap()).unwrap();
        let verified = Self::verify_signature_secp256(
            pubkey,
            prehash.try_into().unwrap(),
            signature,
            &s_inverse,
            ec_params,
        );
        if verified {
            Ok(())
        } else {
            Err(Error::new())
        }
    }

    /// Verify the prehashed message against the provided ECDSA signature.
    ///
    /// Accepts the following arguments:
    /// - `pubkey`: The public key to verify the signature against. The public key is in uncompressed form. The points
    /// are represented as big-endian bytes and need to be converted to little endian to instantiate the Secp256k1Point.
    /// - `msg_hash`: The prehashed message to verify the signature against.
    /// - `signature`: The signature to verify.
    /// - `s_inverse`: The inverse of the scalar `s` in the signature.
    ///
    /// This function is a modified version of [`crate::hazmat::verify_prehashed`] with
    /// changes implemented to support SP1 acceleration.
    #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
    pub fn verify_signature_secp256(
        pubkey: &[u8; 65],
        msg_hash: &[u8; 32],
        signature: &Signature<C>,
        s_inverse: &Scalar<C>,
        curve_id: u8,
    ) -> bool {
        let mut pubkey_x_le_bytes = pubkey[1..33].to_vec();
        pubkey_x_le_bytes.reverse();
        let mut pubkey_y_le_bytes = pubkey[33..].to_vec();
        pubkey_y_le_bytes.reverse();

        // Split the signature into its two scalars.
        let (r, s) = signature.split_scalars();
        assert_eq!(*s_inverse * s.as_ref(), Scalar::<C>::ONE);
        // Convert the message hash into a scalar.
        let field = bits2field::<C>(msg_hash);
        if field.is_err() {
            return false;
        }
        let field: Scalar<C> = Scalar::<C>::from_repr(field.unwrap()).unwrap();
        let z = field;
        // Compute the two scalars.
        let u1 = z * s_inverse;
        let u2 = *r * s_inverse;
        // Convert u1 and u2 to "little-endian" bits (LSb first with little-endian byte order) for the MSM.
        let (u1_be_bytes, u2_be_bytes) = (u1.to_repr(), u2.to_repr());
        let u1_le_bits = be_bytes_to_le_bits(u1_be_bytes.as_slice().try_into().unwrap());
        let u2_le_bits = be_bytes_to_le_bits(u2_be_bytes.as_slice().try_into().unwrap());

        // Compute the MSM.
        let x_bytes_be = match curve_id {
            1 => {
                let point = Secp256k1Point::multi_scalar_multiplication(
                    &u1_le_bits,
                    Secp256k1Point::new(Secp256k1Point::GENERATOR),
                    &u2_le_bits,
                    Secp256k1Point::from_le_bytes(&[pubkey_x_le_bytes, pubkey_y_le_bytes].concat()),
                );
                let p = point.unwrap();

                // Convert the result of the MSM into a scalar and confirm that it matches the R value of the signature.
                let mut x_bytes_be = [0u8; 32];
                x_bytes_be[..32].copy_from_slice(&p.to_le_bytes()[..32]);
                x_bytes_be.reverse();
                x_bytes_be
            }
            2 => {
                let point = Secp256r1Point::multi_scalar_multiplication(
                    &u1_le_bits,
                    Secp256r1Point::new(Secp256r1Point::GENERATOR),
                    &u2_le_bits,
                    Secp256r1Point::from_le_bytes(&[pubkey_x_le_bytes, pubkey_y_le_bytes].concat()),
                );
                let p = point.unwrap();

                // Convert the result of the MSM into a scalar and confirm that it matches the R value of the signature.
                let mut x_bytes_be = [0u8; 32];
                x_bytes_be[..32].copy_from_slice(&p.to_le_bytes()[..32]);
                x_bytes_be.reverse();
                x_bytes_be
            }
        };

        let x_field = bits2field::<C>(&x_bytes_be);
        if x_field.is_err() {
            return false;
        }
        return *r == Scalar::<C>::from_repr(x_field.unwrap()).unwrap();
    }
}

//
// `*Verifier` trait impls
//

impl<C, D> DigestVerifier<D, Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify_digest(&self, msg_digest: D, signature: &Signature<C>) -> Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
                PrehashVerifier::<Signature<C>>::verify_prehash(self, &msg_digest.finalize_fixed(), signature)?;
                return Ok(());
            }
        }
        self.inner.as_affine().verify_digest(msg_digest, signature)
    }
}

impl<C> PrehashVerifier<Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature<C>) -> Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
                let ec_params = ec_params_256_bit::<C>();
                let point = self.inner.to_encoded_point(false);
                let pubkey = point.as_bytes();
                let pubkey_array: &[u8; 65] = pubkey.try_into().unwrap();
                Self::verify_prehash_secp256(pubkey_array, prehash, signature, ec_params)?;
                return Ok(());
            }

        }
        let field = bits2field::<C>(prehash)?;
        self.inner.as_affine().verify_prehashed(&field, signature)
    }
}

impl<C> Verifier<Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<()> {
        self.verify_digest(C::Digest::new_with_prefix(msg), signature)
    }
}

#[cfg(feature = "sha2")]
impl<C> Verifier<SignatureWithOid<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], sig: &SignatureWithOid<C>) -> Result<()> {
        match sig.oid() {
            ECDSA_SHA224_OID => self.verify_prehash(&Sha224::digest(msg), sig.signature()),
            ECDSA_SHA256_OID => self.verify_prehash(&Sha256::digest(msg), sig.signature()),
            ECDSA_SHA384_OID => self.verify_prehash(&Sha384::digest(msg), sig.signature()),
            ECDSA_SHA512_OID => self.verify_prehash(&Sha512::digest(msg), sig.signature()),
            _ => Err(Error::new()),
        }
    }
}

#[cfg(feature = "der")]
impl<C, D> DigestVerifier<D, der::Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    fn verify_digest(&self, msg_digest: D, signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        DigestVerifier::<D, Signature<C>>::verify_digest(self, msg_digest, &signature)
    }
}

#[cfg(feature = "der")]
impl<C> PrehashVerifier<der::Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        PrehashVerifier::<Signature<C>>::verify_prehash(self, prehash, &signature)
    }
}

#[cfg(feature = "der")]
impl<C> Verifier<der::Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        Verifier::<Signature<C>>::verify(self, msg, &signature)
    }
}

//
// Other trait impls
//

impl<C> AsRef<AffinePoint<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn as_ref(&self) -> &AffinePoint<C> {
        self.as_affine()
    }
}

impl<C> Copy for VerifyingKey<C> where C: PrimeCurve + CurveArithmetic {}

impl<C> From<VerifyingKey<C>> for CompressedPoint<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: VerifyingKey<C>) -> CompressedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<&VerifyingKey<C>> for CompressedPoint<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: &VerifyingKey<C>) -> CompressedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<VerifyingKey<C>> for EncodedPoint<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: VerifyingKey<C>) -> EncodedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<&VerifyingKey<C>> for EncodedPoint<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: &VerifyingKey<C>) -> EncodedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> Eq for VerifyingKey<C> where C: PrimeCurve + CurveArithmetic {}

impl<C> PartialEq for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl<C> From<PublicKey<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn from(public_key: PublicKey<C>) -> VerifyingKey<C> {
        VerifyingKey { inner: public_key }
    }
}

impl<C> From<&PublicKey<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn from(public_key: &PublicKey<C>) -> VerifyingKey<C> {
        (*public_key).into()
    }
}

impl<C> From<VerifyingKey<C>> for PublicKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn from(verifying_key: VerifyingKey<C>) -> PublicKey<C> {
        verifying_key.inner
    }
}

impl<C> From<&VerifyingKey<C>> for PublicKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn from(verifying_key: &VerifyingKey<C>) -> PublicKey<C> {
        (*verifying_key).into()
    }
}

impl<C> PartialOrd for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl<C> Ord for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<C> TryFrom<&[u8]> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_sec1_bytes(bytes)
    }
}

#[cfg(feature = "pkcs8")]
impl<C> AssociatedAlgorithmIdentifier for VerifyingKey<C>
where
    C: AssociatedOid + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<ObjectIdentifier> =
        PublicKey::<C>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "pkcs8")]
impl<C> SignatureAlgorithmIdentifier for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<C>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "pkcs8")]
impl<C> TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for VerifyingKey<C>
where
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = pkcs8::spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        PublicKey::try_from(spki).map(|inner| Self { inner })
    }
}

#[cfg(feature = "pem")]
impl<C> EncodePublicKey for VerifyingKey<C>
where
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        self.inner.to_public_key_der()
    }
}

#[cfg(feature = "pem")]
impl<C> FromStr for VerifyingKey<C>
where
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_public_key_pem(s).map_err(|_| Error::new())
    }
}

#[cfg(all(feature = "pem", feature = "serde"))]
impl<C> Serialize for VerifyingKey<C>
where
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(all(feature = "pem", feature = "serde"))]
impl<'de, C> Deserialize<'de> for VerifyingKey<C>
where
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        PublicKey::<C>::deserialize(deserializer).map(Into::into)
    }
}
