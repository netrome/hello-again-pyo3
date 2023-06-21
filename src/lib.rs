use pyo3::prelude::*;
use secp256k1::hashes::sha256;

#[pyclass]
pub struct Secp256k1(secp256k1::Secp256k1<secp256k1::All>);

#[pyclass]
pub struct SecretKey(secp256k1::SecretKey);

#[pyclass]
pub struct PublicKey(secp256k1::PublicKey);

#[pymethods]
impl Secp256k1 {
    #[new]
    pub fn new() -> Self {
        Self(secp256k1::Secp256k1::new())
    }

    pub fn generate_keypair(&self) -> (SecretKey, PublicKey) {
        let (sk, pk) = self.0.generate_keypair(&mut rand::thread_rng());

        (SecretKey(sk), PublicKey(pk))
    }

    pub fn hash_sign_ecdsa(&self, msg: &str, secret_key: &SecretKey) -> [u8; 64] {
        let hashed_msg = secp256k1::Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
        self.0
            .sign_ecdsa(&hashed_msg, &secret_key.0)
            .serialize_compact()
    }
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn hello_pyo3(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Secp256k1>()?;
    m.add_class::<SecretKey>()?;
    m.add_class::<PublicKey>()?;
    Ok(())
}
