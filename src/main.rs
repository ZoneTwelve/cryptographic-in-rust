// This program demonstrates the use of the ed25519-dalek library (v2.x) for
// creating and verifying Ed25519 digital signatures.

// Import the RngCore trait to get access to the `fill_bytes` method.
use rand::RngCore;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature, SecretKey};

fn main() {
    // 1. Key Generation
    // -----------------
    // The compiler has guided us to use `SigningKey::from_bytes`. This requires a
    // `SecretKey`, which is a 32-byte array. We generate these bytes using a
    // secure random number generator from the `rand` crate.

    // First, create a source of cryptographically secure randomness.
    let mut csprng = OsRng;

    // Next, generate 32 random bytes into a byte array.
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);

    // Create the `SecretKey` type from the raw bytes.
    let secret_key = SecretKey::from(secret_key_bytes);

    // Now, create the `SigningKey` from the secret bytes.
    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // The public key can be converted to a byte array for storage or transmission.
    let public_key_bytes: [u8; 32] = verifying_key.to_bytes();

    // ** FIX HERE **
    // The `secret_key` variable is already a byte array `[u8; 32]`.
    // We can print it directly without calling any methods on it.
    println!("Public Key (bytes): {:?}", public_key_bytes);
    println!("Secret Key (bytes): {:?}", secret_key);
    println!("---");

    // 2. Message Signing
    // ------------------
    // A message is defined as a byte slice. The signing key is used to sign
    // this message, producing a digital signature.
    let message: &[u8] = b"This is a test message for Ed25519 signing.";
    let signature: Signature = signing_key.sign(message);

    // The signature can also be converted to a byte array.
    let signature_bytes: [u8; 64] = signature.to_bytes();

    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature (bytes): {:?}", signature_bytes);
    println!("---");

    // 3. Signature Verification
    // -------------------------
    // The public key (VerifyingKey), the original message, and the signature are used to
    // verify the authenticity of the message.
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature is valid!"),
        Err(_) => println!("Signature is invalid!"),
    }

    // Example of a failed verification with a tampered message.
    let tampered_message: &[u8] = b"This is a tampered message.";
    match verifying_key.verify(tampered_message, &signature) {
        Ok(_) => println!("This should not happen! Tampered message was verified!"),
        Err(e) => println!("Signature verification failed as expected: {}", e),
    }
}

