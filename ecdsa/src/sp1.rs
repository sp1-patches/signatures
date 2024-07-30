use crate::{Error, RecoveryId, Result};
use digest::generic_array::ArrayLength;
use elliptic_curve::ops::Invert;
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
    /// This function is only enabled inside of SP1 programs, and accelerates the
    /// recovery process using SP1 syscalls for secp256k1.
    #[allow(non_snake_case)]
    pub fn recover_from_prehash_secp256k1(
        prehash: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self> {
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        let (compressed_pubkey, s_inv) = Self::unconstrained_ecrecover(
            sig_bytes.as_slice().try_into().unwrap(),
            prehash.try_into().unwrap(),
        );

        let pubkey = Self::decompress_pubkey(&compressed_pubkey)?;

        let verified = Self::verify_signature(
            &pubkey,
            &prehash.try_into().unwrap(),
            &Signature::from_slice(&sig_bytes[..64]).unwrap(),
            Some(&s_inv),
        );

        if verified {
            VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| Error::new())
        } else {
            Err(Error::new())
        }
    }

    /// Convert a scalar to its little endian bit representation.
    /// TODO: Can we derive bits from the scalar type?
    fn scalar_to_little_endian_bits<const NUM_BITS: usize>(scalar: &Scalar<C>) -> [bool; NUM_BITS] {
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

    /// Verify a signature over a message hash using SP1 acceleration.
    pub fn verify_signature(
        pubkey: &[u8; 65],
        msg_hash: &[u8; 32],
        signature: &Signature<C>,
        s_inverse: Option<&Scalar<C>>,
    ) -> bool {
        // Convert the pubkey into a Secp256k1AffinePoint.
        let pubkey_x: Scalar<C> =
            Scalar::<C>::from_repr(bits2field::<C>(&pubkey[1..33]).unwrap()).unwrap();
        let pubkey_y: Scalar<C> =
            Scalar::<C>::from_repr(bits2field::<C>(&pubkey[33..]).unwrap()).unwrap();
        let mut pubkey_x_le_bytes = pubkey_x.to_repr();
        pubkey_x_le_bytes.reverse();
        let mut pubkey_y_le_bytes = pubkey_y.to_repr();
        pubkey_y_le_bytes.reverse();
        let affine =
            Secp256k1AffinePoint::from_le_bytes(&[pubkey_x_le_bytes, pubkey_y_le_bytes].concat());

        // Split the signature into its two scalars.
        let (r, s) = signature.split_scalars();
        let computed_s_inv;
        let s_inv = match s_inverse {
            Some(s_inv) => {
                assert_eq!(*s_inv * s.as_ref(), Scalar::<C>::ONE);
                s_inv
            }
            None => {
                computed_s_inv = s.invert();
                &computed_s_inv
            }
        };

        // Convert the message hash into a scalar.
        let field = bits2field::<C>(msg_hash);
        if field.is_err() {
            return false;
        }
        let field: Scalar<C> = Scalar::<C>::from_repr(field.unwrap()).unwrap();
        let z = field;

        // Compute the two scalars.
        let u1 = z * s_inv;
        let u2 = *r * s_inv;

        // Convert u1 and u2 to little endian bits for the MSM.
        let u1_le_bits = Self::scalar_to_little_endian_bits::<256>(&u1);
        let u2_le_bits = Self::scalar_to_little_endian_bits::<256>(&u2);
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

    /// Outside of the VM, computes the pubkey and s_inverse value from a signature and a message hash.
    ///
    /// WARNING: The values are read from outside of the VM and are not constrained to be correct.
    /// Either use `decompress_pubkey` and `verify_signature` to verify the results of this function, or
    /// use `ecrecover`.
    pub fn unconstrained_ecrecover(sig: &[u8; 65], msg_hash: &[u8; 32]) -> ([u8; 33], Scalar<C>) {
        // The `unconstrained!` wrapper is used since none of these computations directly affect
        // the output values of the VM. The remainder of the function sets the constraints on the values
        // instead. Removing the `unconstrained!` wrapper slightly increases the cycle count.
        unconstrained! {
            let mut buf = [0; 65 + 32];
            let (buf_sig, buf_msg_hash) = buf.split_at_mut(sig.len());
            buf_sig.copy_from_slice(sig);
            buf_msg_hash.copy_from_slice(msg_hash);
            io::write(FD_ECRECOVER_HOOK, &buf);
        }

        let recovered_bytes: [u8; 33] = io::read_vec().try_into().unwrap();

        let s_inv_bytes: [u8; 32] = io::read_vec().try_into().unwrap();
        let s_inverse = Scalar::<C>::from_repr(bits2field::<C>(&s_inv_bytes).unwrap()).unwrap();

        (recovered_bytes, s_inverse)
    }

    /// Convert a compressed pubkey into decompressed form using SP1 acceleration.
    pub fn decompress_pubkey(compressed_pubkey: &[u8; 33]) -> Result<[u8; 65]> {
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
}
