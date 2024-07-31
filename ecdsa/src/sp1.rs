use crate::{Error, RecoveryId, Result};
use digest::generic_array::ArrayLength;
use elliptic_curve::PrimeField;
use elliptic_curve::{
    point::DecompressPoint,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar,
};

use elliptic_curve::Field;
use sp1_lib::io::{self, FD_ECRECOVER_HOOK};
use sp1_lib::unconstrained;
use sp1_lib::{
    secp256k1::Secp256k1AffinePoint, syscall_secp256k1_decompress,
    utils::AffinePoint as Sp1AffinePoint,
};

use crate::{
    hazmat::{bits2field, VerifyPrimitive},
    Signature, SignatureSize, VerifyingKey,
};

#[cfg(feature = "verifying")]
impl<C> VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Recover a [`VerifyingKey`] from the given `prehash` of a message, the
    /// signature over that prehashed message, and a [`RecoveryId`].
    ///
    /// This function leverages SP1 syscalls for secp256k1 to accelerate public key recovery
    /// in the zkVM. After recovery, it verifies the signature against the recovered public key
    /// to ensure correctness.
    pub fn recover_from_prehash_secp256k1(
        prehash: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self> {
        // Recover the compressed public key and s_inverse value from the signature and prehashed message.
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        let (compressed_pubkey, s_inv) =
            recover_ecdsa_unconstrained(&sig_bytes, prehash.try_into().unwrap());

        // Convert the s_inverse bytes to a scalar.
        let s_inverse = Scalar::<C>::from_repr(bits2field::<C>(&s_inv).unwrap()).unwrap();

        // Transform the compressed public key into uncompressed form.
        let pubkey = decompress_pubkey(&compressed_pubkey)?;

        // Verify the signature against the recovered public key. The last byte of the signature
        // is the recovery id, which is not used in the verification process.
        let verified = Self::verify_signature_secp256k1(
            &pubkey,
            &prehash.try_into().unwrap(),
            &Signature::from_slice(&sig_bytes[..64]).unwrap(),
            &s_inverse,
        );

        // If the signature is valid, return the public key.
        if verified {
            VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| Error::new())
        } else {
            Err(Error::new())
        }
    }


    /// Verify the prehashed message against the provided ECDSA signature.
    ///
    /// Accepts the following arguments:
    /// - `pubkey`: The public key to verify the signature against.
    /// - `msg_hash`: The prehashed message to verify the signature against.
    /// - `signature`: The signature to verify.
    /// - `s_inverse`: The inverse of the scalar `s` in the signature.
    ///
    /// This function is a modified version of [`crate::hazmat::verify_prehashed`] with
    /// changes implemented to support SP1 acceleration.
    pub fn verify_signature_secp256k1(
        pubkey: &[u8; 65],
        msg_hash: &[u8; 32],
        signature: &Signature<C>,
        s_inverse: &Scalar<C>,
    ) -> bool {
        let mut pubkey_x_le_bytes = pubkey[1..33].to_vec();
        pubkey_x_le_bytes.reverse();
        let mut pubkey_y_le_bytes = pubkey[33..].to_vec();
        pubkey_y_le_bytes.reverse();
        let affine =
            Secp256k1AffinePoint::from_le_bytes(&[pubkey_x_le_bytes, pubkey_y_le_bytes].concat());

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

        // Convert u1 and u2 to little endian bits for the MSM.
        let (mut u1_le_bytes, mut u2_le_bytes) = (u1.to_repr(), u2.to_repr());
        u1_le_bytes.reverse();
        u2_le_bytes.reverse();
        let u1_le_bits = bytes_to_bits(u1_le_bytes.as_slice().try_into().unwrap());
        let u2_le_bits = bytes_to_bits(u2_le_bytes.as_slice().try_into().unwrap());

        // Compute the MSM.
        let res = Secp256k1AffinePoint::multi_scalar_multiplication(
            &u1_le_bits,
            Secp256k1AffinePoint(Secp256k1AffinePoint::GENERATOR),
            &u2_le_bits,
            affine,
        )
        .unwrap();

        // Convert the result of the MSM into a scalar and confirm that it matches the R value of the signature.
        let mut x_bytes_be = [0u8; 32];
        for i in 0..8 {
            x_bytes_be[i * 4..(i * 4) + 4].copy_from_slice(&res.0[i].to_le_bytes());
        }
        x_bytes_be.reverse();
        let x_field = bits2field::<C>(&x_bytes_be);
        if x_field.is_err() {
            return false;
        }
        *r == Scalar::<C>::from_repr(x_field.unwrap()).unwrap()
    }
}

/// Convert bytes to bits. Used to convert the scalar values to little endian bits for the MSM.
fn bytes_to_bits(bytes: &[u8; 32]) -> [bool; 256] {
    let mut bits = [false; 256];
    for (i, &byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            bits[i * 8 + j] = ((byte >> j) & 1) == 1;
        }
    }
    bits
}

/// Outside of the VM, computes the pubkey and s_inverse value from a signature and a message hash.
///
/// WARNING: The values are read from outside of the VM and are not constrained to be correct. Use
/// [`VerifyingKey::recover_from_prehash_secp256k1`] to securely recover the public key associated with
/// a signature and message hash.
fn recover_ecdsa_unconstrained(sig: &[u8; 65], msg_hash: &[u8; 32]) -> ([u8; 33], [u8; 32]) {
    // The `unconstrained!` wrapper is used to not include the cycles used to get the "hint" for the compressed
    // public key and s_inverse values from a non-zkVM context, because the values will be constrained
    // in the VM.
    unconstrained! {
        let mut buf = [0; 65 + 32];
        let (buf_sig, buf_msg_hash) = buf.split_at_mut(sig.len());
        buf_sig.copy_from_slice(sig);
        buf_msg_hash.copy_from_slice(msg_hash);
        io::write(FD_ECRECOVER_HOOK, &buf);
    }

    let recovered_bytes: [u8; 33] = io::read_vec().try_into().unwrap();
    let s_inv_bytes: [u8; 32] = io::read_vec().try_into().unwrap();

    (recovered_bytes, s_inv_bytes)
}

/// Takes in a compressed public key and decompresses it using the SP1 syscall `syscall_secp256k1_decompress`.
///
/// The first byte of the compressed public key is 0x02 if the y coordinate is even, 0x03 if the y coordinate is odd,
/// and the remaining 32 bytes are the x coordinate of the decompressed pubkey.
///
/// The decompressed public key is 65 bytes long, with 0x04 as the first byte,
/// and the remaining 64 bytes being the x and y coordinates of the decompressed pubkey.
///
/// More details on secp256k1 public key format can be found in the [Bitcoin wiki](https://en.bitcoin.it/wiki/Protocol_documentation#Signatures).
///
/// SAFETY: Our syscall will check that the x and y coordinates are within the
/// secp256k1 scalar field.
fn decompress_pubkey(compressed_pubkey: &[u8; 33]) -> Result<[u8; 65]> {
    let mut decompressed_key: [u8; 64] = [0; 64];
    decompressed_key[..32].copy_from_slice(&compressed_pubkey[1..]);
    let is_odd = match compressed_pubkey[0] {
        2 => false,
        3 => true,
        _ => return Err(Error::new()),
    };
    unsafe {
        syscall_secp256k1_decompress(&mut decompressed_key, is_odd);
    }

    let mut result: [u8; 65] = [0; 65];
    result[0] = 4;
    result[1..].copy_from_slice(&decompressed_key);
    Ok(result)
}
