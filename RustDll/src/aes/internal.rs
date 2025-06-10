use super::Aes;
use super::modes::{
    aes_encrypt_block, aes_decrypt_block,
    pkcs7_pad, pkcs7_unpad,
    xor_block, inc_block,
};

impl Aes {
    pub(crate) fn encrypt_ecb(&self, data: &[u8]) -> Vec<u8> {
        let padded = pkcs7_pad(data);
        return  padded.chunks(16)
            .map(|block| {
                let mut b = [0u8; 16];
                b[..block.len()].copy_from_slice(block);
                aes_encrypt_block(&b, &self.key)
            })
            .flatten()
            .collect();
    }

    pub(crate) fn decrypt_ecb(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            out.extend(aes_decrypt_block(&b, &self.key));
        }
        return pkcs7_unpad(&out);
    }

    pub(crate) fn encrypt_ecb_no_padding(&self, data: &[u8]) -> Vec<u8> {
        return  data.chunks(16)
            .map(|block| {
                let mut b = [0u8; 16];
                b[..block.len()].copy_from_slice(block);
                aes_encrypt_block(&b, &self.key)
            })
            .flatten()
            .collect();
    }

    pub(crate) fn decrypt_ecb_no_padding(&self, data: &[u8]) -> Vec<u8> {
        return data.chunks(16)
            .map(|block| {
                let mut b = [0u8; 16];
                b.copy_from_slice(block);
                aes_decrypt_block(&b, &self.key)
            })
            .flatten()
            .collect();
    }

    pub(crate) fn encrypt_cbc(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let padded = pkcs7_pad(data);
        let mut prev = iv;
        let mut out = vec![];
        for block in padded.chunks(16) {
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &prev);
            let encrypted = aes_encrypt_block(&xored, &self.key);
            out.extend(encrypted);
            prev = encrypted;
        }
        return out;
    }

    pub(crate) fn decrypt_cbc(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut prev = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            let decrypted = aes_decrypt_block(&b, &self.key);
            let xored = xor_block(&decrypted, &prev);
            out.extend(xored);
            prev = b;
        }
        return pkcs7_unpad(&out);
    }

    pub(crate) fn encrypt_cbc_no_padding(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut prev = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &prev);
            let encrypted = aes_encrypt_block(&xored, &self.key);
            out.extend(encrypted);
            prev = encrypted;
        }
        return out;
    }

    pub(crate) fn decrypt_cbc_no_padding(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut prev = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            let decrypted = aes_decrypt_block(&b, &self.key);
            let xored = xor_block(&decrypted, &prev);
            out.extend(xored);
            prev = b;
        }
        return out;
    }

    pub(crate) fn encrypt_ctr(&self, data: &[u8], nonce: [u8; 16]) -> Vec<u8> {
        let mut ctr = nonce;
        let mut out = vec![];
        for block in data.chunks(16) {
            let keystream = aes_encrypt_block(&ctr, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &keystream);
            out.extend(&xored[..block.len()]);
            inc_block(&mut ctr);
        }
        return out;
    }

    pub(crate) fn decrypt_ctr(&self, data: &[u8], nonce: [u8; 16]) -> Vec<u8> {
        return self.encrypt_ctr(data, nonce);
    }

    pub(crate) fn encrypt_ofb(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut ofb = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            ofb = aes_encrypt_block(&ofb, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &ofb);
            out.extend(&xored[..block.len()]);
        }
        return out;
    }

    pub(crate) fn decrypt_ofb(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        return self.encrypt_ofb(data, iv);
    }

    pub(crate) fn encrypt_cfb(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut cfb = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            cfb = aes_encrypt_block(&cfb, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &cfb);
            out.extend(&xored[..block.len()]);
            cfb = xored;
        }
        return  out;
    }

    pub(crate) fn decrypt_cfb(&self, data: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let mut cfb = iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let keystream = aes_encrypt_block(&cfb, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &keystream);
            out.extend(&xored[..block.len()]);
            cfb = b;
        }
        return  out;
    }
} 