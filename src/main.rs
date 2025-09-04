use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use rand::RngCore;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature, SecretKey};

fn main() {
    // 1. Setup Folder
    // -----------------
    // Define the name of the folder to store crypto materials.
    let dir_path = "crypto_keys";

    // Create the directory. `create_dir_all` is convenient because it
    // doesn't return an error if the directory already exists.
    fs::create_dir_all(dir_path)
        .expect("Failed to create directory");
    println!("Using directory: '{}'", dir_path);
    println!("---");


    // 2. Key Generation
    // -----------------
    let mut csprng = OsRng;
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);
    let secret_key = SecretKey::from(secret_key_bytes);
    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let public_key_bytes: [u8; 32] = verifying_key.to_bytes();

    println!("Public Key (bytes): {:?}", public_key_bytes);
    println!("Secret Key (bytes): {:?}", secret_key);
    println!("---");


    // 3. Message Signing
    // ------------------
    let message: &[u8] = b"This is a test message for Ed25519 signing.";
    let signature: Signature = signing_key.sign(message);
    let signature_bytes: [u8; 64] = signature.to_bytes();

    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature (bytes): {:?}", signature_bytes);
    println!("---");

    // 4. Save Keys and Signature to Files
    // -------------------------------------

    // Save the public key
    let public_key_path = Path::new(dir_path).join("public.key");
    let mut public_key_file = File::create(&public_key_path)
        .expect("Failed to create public key file");
    public_key_file.write_all(&public_key_bytes)
        .expect("Failed to write public key to file");
    println!("Public key saved to: {}", public_key_path.display());

    // Save the secret key
    // ** FIX HERE **
    // The `secret_key` variable is already a `[u8; 32]`. We pass a reference
    // to it directly, as `write_all` expects a byte slice (`&[u8]`).
    let secret_key_path = Path::new(dir_path).join("secret.key");
    let mut secret_key_file = File::create(&secret_key_path)
        .expect("Failed to create secret key file");
    secret_key_file.write_all(&secret_key)
        .expect("Failed to write secret key to file");
    println!("Secret key saved to: {}", secret_key_path.display());

    // Save the signature
    let signature_path = Path::new(dir_path).join("message.sig");
    let mut signature_file = File::create(&signature_path)
        .expect("Failed to create signature file");
    signature_file.write_all(&signature_bytes)
        .expect("Failed to write signature to file");
    println!("Signature saved to: {}", signature_path.display());


    // 5. Signature Verification (as before)
    // -------------------------
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("\nVerification successful: Signature is valid!"),
        Err(e) => println!("\nVerification failed: {}", e),
    }
}
