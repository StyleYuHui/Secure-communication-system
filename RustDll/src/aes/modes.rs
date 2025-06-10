pub(crate) const Nb: usize = 4; // 块列数
pub(crate) const Nk: usize = 4; // 密钥字数
pub(crate) const Nr: usize = 10; // 轮数

pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub(crate) const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub(crate) const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
];

pub(crate) fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        return (x << 1) ^ 0x1b;
    } else {
        return x << 1;
    }
}

pub(crate) fn sub_word(word: [u8; 4]) -> [u8; 4] {
    return [SBOX[word[0] as usize], SBOX[word[1] as usize], SBOX[word[2] as usize], SBOX[word[3] as usize]];
}

pub(crate) fn rot_word(word: [u8; 4]) -> [u8; 4] {
    return  [word[1], word[2], word[3], word[0]];
}

pub(crate) fn key_expansion(key: &[u8; 16]) -> [[u8; 4]; Nb * (Nr + 1)] {
    let mut w = [[0u8; 4]; Nb * (Nr + 1)];
    for i in 0..Nk {
        w[i][0] = key[4 * i];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }
    for i in Nk..Nb * (Nr + 1) {
        let mut temp = w[i - 1];
        if i % Nk == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / Nk];
        }
        for j in 0..4 {
            w[i][j] = w[i - Nk][j] ^ temp[j];
        }
    }
    return  w;
}

pub(crate) fn add_round_key(state: &mut [[u8; 4]; 4], w: &[[u8; 4]; Nb * (Nr + 1)], round: usize) {
    for c in 0..Nb {
        for r in 0..4 {
            state[r][c] ^= w[round * Nb + c][r];
        }
    }
}

pub(crate) fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = SBOX[state[r][c] as usize];
        }
    }
}

pub(crate) fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = INV_SBOX[state[r][c] as usize];
        }
    }
}

pub(crate) fn shift_rows(state: &mut [[u8; 4]; 4]) {
    for r in 1..4 {
        state[r].rotate_left(r);
    }
}

pub(crate) fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    for r in 1..4 {
        state[r].rotate_right(r);
    }
}

pub(crate) fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a = state[0][c];
        let b = state[1][c];
        let c_ = state[2][c];
        let d = state[3][c];
        state[0][c] = xtime(a) ^ xtime(b) ^ b ^ c_ ^ d;
        state[1][c] = a ^ xtime(b) ^ xtime(c_) ^ c_ ^ d;
        state[2][c] = a ^ b ^ xtime(c_) ^ xtime(d) ^ d;
        state[3][c] = xtime(a) ^ a ^ b ^ c_ ^ xtime(d);
    }
}

pub(crate) fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a = state[0][c];
        let b = state[1][c];
        let c_ = state[2][c];
        let d = state[3][c];
        state[0][c] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c_, 0x0d) ^ mul(d, 0x09);
        state[1][c] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c_, 0x0b) ^ mul(d, 0x0d);
        state[2][c] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c_, 0x0e) ^ mul(d, 0x0b);
        state[3][c] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c_, 0x09) ^ mul(d, 0x0e);
    }
}

pub(crate) fn mul(x: u8, y: u8) -> u8 {
    let mut r = 0u8;
    let mut a = x;
    let mut b = y;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return  r;
}

pub(crate) fn bytes2state(input: &[u8; 16]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];
    for i in 0..16 {
        state[i % 4][i / 4] = input[i];
    }
    return  state;
}

pub(crate) fn state2bytes(state: &[[u8; 4]; 4]) -> [u8; 16] {
    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = state[i % 4][i / 4];
    }
    return  output;
}

pub(crate) fn aes_encrypt_block(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let w = key_expansion(key);
    let mut state = bytes2state(input);
    add_round_key(&mut state, &w, 0);
    for round in 1..Nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &w, round);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &w, Nr);
    return  state2bytes(&state);
}

pub(crate) fn aes_decrypt_block(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let w = key_expansion(key);
    let mut state = bytes2state(input);
    add_round_key(&mut state, &w, Nr);
    for round in (1..Nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &w, round);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &w, 0);
    return  state2bytes(&state);
}

// ================== 分组加密模式实现 ===================

pub(crate) fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    return  out;
}

pub(crate) fn inc_block(block: &mut [u8; 16]) {
    for i in (0..16).rev() {
        if block[i] == 0xff {
            block[i] = 0;
        } else {
            block[i] += 1;
            break;
        }
    }
}

pub(crate) fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut out = data.to_vec();
    out.extend(vec![pad_len as u8; pad_len]);
    return  out;
}

pub(crate) fn pkcs7_unpad(data: &[u8]) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return data.to_vec();
    }
    return  data[..data.len() - pad_len].to_vec();
}

pub struct Aes128 {
    pub key: [u8; 16],
}

impl Aes128 {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    // ECB模式
    pub fn encrypt_ecb(&self, data: &[u8]) -> Vec<u8> {
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
    pub fn decrypt_ecb(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            out.extend(aes_decrypt_block(&b, &self.key));
        }
        return  pkcs7_unpad(&out);
    }

    // CBC模式
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let padded = pkcs7_pad(data);
        let mut prev = *iv;
        let mut out = vec![];
        for block in padded.chunks(16) {
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &prev);
            let encrypted = aes_encrypt_block(&xored, &self.key);
            out.extend(encrypted);
            prev = encrypted;
        }
        return  out;
    }
    pub fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut prev = *iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            let decrypted = aes_decrypt_block(&b, &self.key);
            let xored = xor_block(&decrypted, &prev);
            out.extend(xored);
            prev = b;
        }
        return  pkcs7_unpad(&out);
    }

    // CTR模式
    pub fn encrypt_ctr(&self, data: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
        let mut ctr = *nonce;
        let mut out = vec![];
        for block in data.chunks(16) {
            let keystream = aes_encrypt_block(&ctr, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &keystream);
            out.extend(&xored[..block.len()]);
            inc_block(&mut ctr);
        }
        return  out;
    }
    pub fn decrypt_ctr(&self, data: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
        self.encrypt_ctr(data, nonce) // CTR加解密对称
    }

    // OFB模式
    pub fn encrypt_ofb(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut ofb = *iv;
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
    pub fn decrypt_ofb(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        return  self.encrypt_ofb(data, iv); // OFB加解密对称
    }

    // CFB模式
    pub fn encrypt_cfb(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut cfb = *iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            cfb = aes_encrypt_block(&cfb, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &cfb);
            out.extend(&xored[..block.len()]);
            cfb = xored;
        }
        return out;
    }
    pub fn decrypt_cfb(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut cfb = *iv;
        let mut out = vec![];
        for block in data.chunks(16) {
            let keystream = aes_encrypt_block(&cfb, &self.key);
            let mut b = [0u8; 16];
            b[..block.len()].copy_from_slice(block);
            let xored = xor_block(&b, &keystream);
            out.extend(&xored[..block.len()]);
            cfb = b;
        }
        return out;
    }
}

// 生成随机密钥和IV（仅用于演示）
pub fn generate_random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = (i as u8).wrapping_mul(17).wrapping_add(23);
    }
    return key;
}

pub fn generate_random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    for i in 0..16 {
        iv[i] = (i as u8).wrapping_mul(31).wrapping_add(77);
    }
    return iv;
}
