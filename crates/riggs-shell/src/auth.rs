use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub struct ShellAuth {
    authorized_keys: Vec<VerifyingKey>,
}

impl ShellAuth {
    pub fn new() -> Self {
        Self {
            authorized_keys: Vec::new(),
        }
    }

    pub fn add_authorized_key(&mut self, key: VerifyingKey) {
        self.authorized_keys.push(key);
    }

    pub fn verify_challenge(
        &self,
        public_key: &VerifyingKey,
        challenge: &[u8],
        signature: &Signature,
    ) -> bool {
        if !self.authorized_keys.iter().any(|k| k == public_key) {
            return false;
        }
        public_key.verify(challenge, signature).is_ok()
    }
}

impl Default for ShellAuth {
    fn default() -> Self {
        Self::new()
    }
}
