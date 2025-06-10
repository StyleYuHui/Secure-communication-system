mod internal;

use std::fmt;
use rand::Rng;

/// AES加密模式
#[derive(Debug, Clone, Copy)]
pub enum AesMode {
    /// ECB模式（带填充）
    Ecb,
    /// ECB模式（无填充）
    EcbNoPadding,
    /// CBC模式（带填充）
    Cbc,
    /// CBC模式（无填充）
    CbcNoPadding,
    /// CTR模式
    Ctr,
    /// OFB模式
    Ofb,
    /// CFB模式
    Cfb,
}

impl fmt::Display for AesMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AesMode::Ecb => write!(f, "ECB (带填充)"),
            AesMode::EcbNoPadding => write!(f, "ECB (无填充)"),
            AesMode::Cbc => write!(f, "CBC (带填充)"),
            AesMode::CbcNoPadding => write!(f, "CBC (无填充)"),
            AesMode::Ctr => write!(f, "CTR"),
            AesMode::Ofb => write!(f, "OFB"),
            AesMode::Cfb => write!(f, "CFB"),
        }
    }
}

/// AES加密器
pub struct Aes {
    key: [u8; 16],
}

impl Aes {
    /// 创建新的AES加密器实例
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// 加密数据
    pub fn encrypt(&self, data: &[u8], mode: AesMode, iv: Option<[u8; 16]>) -> Vec<u8> {
        match mode {
            AesMode::Ecb => self.encrypt_ecb(data),
            AesMode::EcbNoPadding => self.encrypt_ecb_no_padding(data),
            AesMode::Cbc => self.encrypt_cbc(data, iv.unwrap_or([0; 16])),
            AesMode::CbcNoPadding => self.encrypt_cbc_no_padding(data, iv.unwrap_or([0; 16])),
            AesMode::Ctr => self.encrypt_ctr(data, iv.unwrap_or([0; 16])),
            AesMode::Ofb => self.encrypt_ofb(data, iv.unwrap_or([0; 16])),
            AesMode::Cfb => self.encrypt_cfb(data, iv.unwrap_or([0; 16])),
        }
    }

    /// 解密数据
    pub fn decrypt(&self, data: &[u8], mode: AesMode, iv: Option<[u8; 16]>) -> Vec<u8> {
        match mode {
            AesMode::Ecb => self.decrypt_ecb(data),
            AesMode::EcbNoPadding => self.decrypt_ecb_no_padding(data),
            AesMode::Cbc => self.decrypt_cbc(data, iv.unwrap_or([0; 16])),
            AesMode::CbcNoPadding => self.decrypt_cbc_no_padding(data, iv.unwrap_or([0; 16])),
            AesMode::Ctr => self.decrypt_ctr(data, iv.unwrap_or([0; 16])),
            AesMode::Ofb => self.decrypt_ofb(data, iv.unwrap_or([0; 16])),
            AesMode::Cfb => self.decrypt_cfb(data, iv.unwrap_or([0; 16])),
        }
    }
}

/// 将字节数组转换为十六进制字符串
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

/// 生成随机密钥
pub fn generate_random_key() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    key
}

/// 生成随机IV
pub fn generate_random_iv() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    iv
}

pub mod modes; 