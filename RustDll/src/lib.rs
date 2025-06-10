// 导出AES模块
pub mod aes;
use aes::{Aes, AesMode, bytes_to_hex, generate_random_key, generate_random_iv};

// 导出RSA模块
pub mod Rsa;
use Rsa::rsa;
use num_bigint::BigUint;
use std::str::FromStr;

// 导出ElGamal模块
pub mod ElGamal;
use ElGamal::elgamal;

// 错误码定义
pub const CRYPTO_SUCCESS: i32 = 0;
pub const CRYPTO_ERROR_INVALID_PARAMETER: i32 = -1;
pub const CRYPTO_ERROR_BUFFER_TOO_SMALL: i32 = -2;
pub const CRYPTO_ERROR_INTERNAL: i32 = -3;

// C兼容的结构体定义
#[repr(C)]
pub struct ByteArray {
    data: *mut u8,
    len: usize,
}

// 辅助函数：十六进制字符串转字节数组
fn hex_to_bytes(hex_str: *const u8, hex_len: usize) -> Result<[u8; 16], i32> {
    if hex_str.is_null() {
        return Err(CRYPTO_ERROR_INVALID_PARAMETER);
    }
    
    // 确保我们不包括结尾的null字符（如果有的话）
    let actual_len = if hex_len > 0 && unsafe { *hex_str.add(hex_len - 1) } == 0 {
        hex_len - 1
    } else {
        hex_len
    };
    
    let hex = unsafe { std::slice::from_raw_parts(hex_str, actual_len) };
    let hex_str = match std::str::from_utf8(hex) {
        Ok(s) => s,
        Err(_) => return Err(CRYPTO_ERROR_INVALID_PARAMETER),
    };
    
    let mut bytes = [0u8; 16];
    
    // 处理十六进制字符串，确保即使长度不足32个字符也能正确处理
    let hex_chars = hex_str.chars().collect::<Vec<_>>();
    let mut i = 0;
    
    while i < 16 {
        let pos = i * 2;
        if pos + 1 < hex_chars.len() {
            // 有两个字符可用于当前字节
            let hex_byte = format!("{}{}", hex_chars[pos], hex_chars[pos + 1]);
            bytes[i] = match u8::from_str_radix(&hex_byte, 16) {
                Ok(b) => b,
                Err(_) => return Err(CRYPTO_ERROR_INVALID_PARAMETER),
            };
        } else if pos < hex_chars.len() {
            // 只有一个字符可用于当前字节，将其视为高位为0
            let hex_byte = format!("0{}", hex_chars[pos]);
            bytes[i] = match u8::from_str_radix(&hex_byte, 16) {
                Ok(b) => b,
                Err(_) => return Err(CRYPTO_ERROR_INVALID_PARAMETER),
            };
        } else {
            // 没有更多字符，剩余字节保持为0
            break;
        }
        i += 1;
    }
    
    Ok(bytes)
}

// 辅助函数：将Rust的Vec<u8>写入C兼容的缓冲区
fn write_to_buffer(data: &[u8], out_buffer: *mut u8, out_len: *mut usize) -> i32 {
    if out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    unsafe {
        let buffer_size = *out_len;
        if buffer_size < data.len() {
            *out_len = data.len();
            return CRYPTO_ERROR_BUFFER_TOO_SMALL;
        }
        
        std::ptr::copy_nonoverlapping(data.as_ptr(), out_buffer, data.len());
        *out_len = data.len();
    }
    
    CRYPTO_SUCCESS
}

// 辅助函数：将字符串写入C兼容的缓冲区
fn write_string_to_buffer(s: &str, out_buffer: *mut u8, out_len: *mut usize) -> i32 {
    write_to_buffer(s.as_bytes(), out_buffer, out_len)
}

// 重新导出AES的各种模式函数
// ECB模式（带填充）
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ecb_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::Ecb, None);
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ecb_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::Ecb, None);
    write_to_buffer(&result, out_buffer, out_len)
}

// ECB模式（无填充）
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ecb_no_padding_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::EcbNoPadding, None);
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ecb_no_padding_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::EcbNoPadding, None);
    write_to_buffer(&result, out_buffer, out_len)
}

// CBC模式（带填充）
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cbc_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::Cbc, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cbc_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::Cbc, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

// CBC模式（无填充）
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cbc_no_padding_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::CbcNoPadding, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cbc_no_padding_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::CbcNoPadding, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

// CTR模式
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ctr_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    nonce_hex: *const u8, nonce_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let nonce = match hex_to_bytes(nonce_hex, nonce_hex_len) {
        Ok(nonce) => nonce,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::Ctr, Some(nonce));
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ctr_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    nonce_hex: *const u8, nonce_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let nonce = match hex_to_bytes(nonce_hex, nonce_hex_len) {
        Ok(nonce) => nonce,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::Ctr, Some(nonce));
    write_to_buffer(&result, out_buffer, out_len)
}

// OFB模式
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ofb_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::Ofb, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_ofb_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::Ofb, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

// CFB模式
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cfb_encrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.encrypt(data_slice, AesMode::Cfb, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_aes_cfb_decrypt(
    key_hex: *const u8, key_hex_len: usize,
    iv_hex: *const u8, iv_hex_len: usize,
    data: *const u8, data_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if data.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    let key = match hex_to_bytes(key_hex, key_hex_len) {
        Ok(k) => k,
        Err(e) => return e,
    };
    
    let iv = match hex_to_bytes(iv_hex, iv_hex_len) {
        Ok(iv) => iv,
        Err(e) => return e,
    };
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let aes = Aes::new(key);
    
    let result = aes.decrypt(data_slice, AesMode::Cfb, Some(iv));
    write_to_buffer(&result, out_buffer, out_len)
}

// 导出RSA相关函数
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_rsa_generate_keys(
    bit_length: usize,
    n_buffer: *mut u8, n_len: *mut usize,
    e_buffer: *mut u8, e_len: *mut usize,
    d_buffer: *mut u8, d_len: *mut usize
) -> i32 {
    if n_buffer.is_null() || n_len.is_null() || 
       e_buffer.is_null() || e_len.is_null() || 
       d_buffer.is_null() || d_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 生成RSA密钥对
    let rsa = rsa::RSA::new(bit_length);
    let (n, e) = rsa.public_key();
    let (_, d) = rsa.private_key();
    
    // 写入n值
    let result = write_string_to_buffer(&n, n_buffer, n_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入e值
    let result = write_string_to_buffer(&e, e_buffer, e_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入d值
    write_string_to_buffer(&d, d_buffer, d_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_rsa_encrypt(
    n: *const u8, n_len: usize,
    e: *const u8, e_len: usize,
    message: *const u8, message_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if n.is_null() || e.is_null() || message.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let n_slice = std::slice::from_raw_parts(n, n_len);
    let e_slice = std::slice::from_raw_parts(e, e_len);
    let message_slice = std::slice::from_raw_parts(message, message_len);
    
    let n_str = match std::str::from_utf8(n_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let e_str = match std::str::from_utf8(e_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建RSA实例并加密
    let rsa = rsa::RSA::from_public_key(n_str, e_str);
    
    let encrypted = rsa.encrypt(message_slice);
    write_to_buffer(&encrypted, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_rsa_decrypt(
    n: *const u8, n_len: usize,
    d: *const u8, d_len: usize,
    ciphertext: *const u8, ciphertext_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if n.is_null() || d.is_null() || ciphertext.is_null() || out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let n_slice = std::slice::from_raw_parts(n, n_len);
    let d_slice = std::slice::from_raw_parts(d, d_len);
    let ciphertext_slice = std::slice::from_raw_parts(ciphertext, ciphertext_len);
    
    let n_str = match std::str::from_utf8(n_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let d_str = match std::str::from_utf8(d_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建RSA实例并解密
    let rsa = rsa::RSA::from_private_key(n_str, d_str);
    
    let decrypted = rsa.decrypt(ciphertext_slice);
    write_to_buffer(&decrypted, out_buffer, out_len)
}

// 导出ElGamal相关函数
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_elgamal_generate_keys(
    bit_length: usize,
    p_buffer: *mut u8, p_len: *mut usize,
    g_buffer: *mut u8, g_len: *mut usize,
    y_buffer: *mut u8, y_len: *mut usize,
    x_buffer: *mut u8, x_len: *mut usize
) -> i32 {
    if p_buffer.is_null() || p_len.is_null() ||
       g_buffer.is_null() || g_len.is_null() ||
       y_buffer.is_null() || y_len.is_null() ||
       x_buffer.is_null() || x_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 生成ElGamal密钥对
    let keys = elgamal::ElGamalKeys::new(bit_length);
    let (p, g, y) = keys.public_key();
    let (_, _, x) = keys.private_key();
    
    // 写入p值
    let result = write_string_to_buffer(&p, p_buffer, p_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入g值
    let result = write_string_to_buffer(&g, g_buffer, g_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入y值
    let result = write_string_to_buffer(&y, y_buffer, y_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入x值
    write_string_to_buffer(&x, x_buffer, x_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_elgamal_encrypt(
    p: *const u8, p_len: usize,
    g: *const u8, g_len: usize,
    y: *const u8, y_len: usize,
    message: *const u8, message_len: usize,
    c1_buffer: *mut u8, c1_len: *mut usize,
    c2_buffer: *mut u8, c2_len: *mut usize
) -> i32 {
    if p.is_null() || g.is_null() || y.is_null() || message.is_null() ||
       c1_buffer.is_null() || c1_len.is_null() ||
       c2_buffer.is_null() || c2_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let p_slice = std::slice::from_raw_parts(p, p_len);
    let g_slice = std::slice::from_raw_parts(g, g_len);
    let y_slice = std::slice::from_raw_parts(y, y_len);
    let message_slice = std::slice::from_raw_parts(message, message_len);
    
    let p_str = match std::str::from_utf8(p_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let g_str = match std::str::from_utf8(g_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let y_str = match std::str::from_utf8(y_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let message_str = match std::str::from_utf8(message_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建ElGamal实例并加密
    let keys = elgamal::ElGamalKeys::from_public_params(p_str, g_str, y_str);
    
    // 将消息转换为BigUint
    let message_hash = elgamal::sha256_to_biguint(message_str);
    
    // 加密消息
    let ciphertext = keys.encrypt(&message_hash);
    
    // 写入c1值
    let c1_str = ciphertext.c1.to_str_radix(10);
    let result = write_string_to_buffer(&c1_str, c1_buffer, c1_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入c2值
    let c2_str = ciphertext.c2.to_str_radix(10);
    write_string_to_buffer(&c2_str, c2_buffer, c2_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_elgamal_decrypt(
    p: *const u8, p_len: usize,
    g: *const u8, g_len: usize,
    x: *const u8, x_len: usize,
    c1: *const u8, c1_len: usize,
    c2: *const u8, c2_len: usize,
    out_buffer: *mut u8, out_len: *mut usize
) -> i32 {
    if p.is_null() || g.is_null() || x.is_null() || 
       c1.is_null() || c2.is_null() ||
       out_buffer.is_null() || out_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let p_slice = std::slice::from_raw_parts(p, p_len);
    let g_slice = std::slice::from_raw_parts(g, g_len);
    let x_slice = std::slice::from_raw_parts(x, x_len);
    let c1_slice = std::slice::from_raw_parts(c1, c1_len);
    let c2_slice = std::slice::from_raw_parts(c2, c2_len);
    
    let p_str = match std::str::from_utf8(p_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let g_str = match std::str::from_utf8(g_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let x_str = match std::str::from_utf8(x_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let c1_str = match std::str::from_utf8(c1_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let c2_str = match std::str::from_utf8(c2_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建ElGamal实例
    let keys = elgamal::ElGamalKeys::from_private_params(p_str, g_str, x_str);
    
    // 解析c1和c2
    let c1_big = match BigUint::from_str(c1_str) {
        Ok(n) => n,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let c2_big = match BigUint::from_str(c2_str) {
        Ok(n) => n,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let ciphertext = elgamal::ElGamalCiphertext {
        c1: c1_big,
        c2: c2_big,
    };
    
    // 解密并返回结果
    let decrypted = keys.decrypt(&ciphertext);
    let decrypted_str = decrypted.to_str_radix(10);
    
    write_string_to_buffer(&decrypted_str, out_buffer, out_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_elgamal_sign(
    p: *const u8, p_len: usize,
    g: *const u8, g_len: usize,
    x: *const u8, x_len: usize,
    message: *const u8, message_len: usize,
    r_buffer: *mut u8, r_len: *mut usize,
    s_buffer: *mut u8, s_len: *mut usize
) -> i32 {
    if p.is_null() || g.is_null() || x.is_null() || message.is_null() ||
       r_buffer.is_null() || r_len.is_null() ||
       s_buffer.is_null() || s_len.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let p_slice = std::slice::from_raw_parts(p, p_len);
    let g_slice = std::slice::from_raw_parts(g, g_len);
    let x_slice = std::slice::from_raw_parts(x, x_len);
    let message_slice = std::slice::from_raw_parts(message, message_len);
    
    let p_str = match std::str::from_utf8(p_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let g_str = match std::str::from_utf8(g_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let x_str = match std::str::from_utf8(x_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let message_str = match std::str::from_utf8(message_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建ElGamal实例
    let keys = elgamal::ElGamalKeys::from_private_params(p_str, g_str, x_str);
    
    // 计算消息哈希
    let message_hash = elgamal::sha256_to_biguint(message_str);
    
    // 签名消息
    let signature = keys.sign(&message_hash);
    
    // 写入r值
    let r_str = signature.r.to_str_radix(10);
    let result = write_string_to_buffer(&r_str, r_buffer, r_len);
    if result != CRYPTO_SUCCESS {
        return result;
    }
    
    // 写入s值
    let s_str = signature.s.to_str_radix(10);
    write_string_to_buffer(&s_str, s_buffer, s_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_elgamal_verify(
    p: *const u8, p_len: usize,
    g: *const u8, g_len: usize,
    y: *const u8, y_len: usize,
    message: *const u8, message_len: usize,
    r: *const u8, r_len: usize,
    s: *const u8, s_len: usize
) -> i32 {
    if p.is_null() || g.is_null() || y.is_null() || message.is_null() || 
       r.is_null() || s.is_null() {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // 转换为字符串
    let p_slice = std::slice::from_raw_parts(p, p_len);
    let g_slice = std::slice::from_raw_parts(g, g_len);
    let y_slice = std::slice::from_raw_parts(y, y_len);
    let message_slice = std::slice::from_raw_parts(message, message_len);
    let r_slice = std::slice::from_raw_parts(r, r_len);
    let s_slice = std::slice::from_raw_parts(s, s_len);
    
    let p_str = match std::str::from_utf8(p_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let g_str = match std::str::from_utf8(g_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let y_str = match std::str::from_utf8(y_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let message_str = match std::str::from_utf8(message_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let r_str = match std::str::from_utf8(r_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let s_str = match std::str::from_utf8(s_slice) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    // 创建ElGamal实例
    let keys = elgamal::ElGamalKeys::from_public_params(p_str, g_str, y_str);
    
    // 将消息转换为BigUint
    let message_hash = elgamal::sha256_to_biguint(message_str);
    
    // 解析r和s
    let r_big = match BigUint::from_str(r_str) {
        Ok(n) => n,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let s_big = match BigUint::from_str(s_str) {
        Ok(n) => n,
        Err(_) => return CRYPTO_ERROR_INVALID_PARAMETER,
    };
    
    let signature = elgamal::ElGamalSignature {
        r: r_big,
        s: s_big,
    };
    
    // 验证签名
    if keys.verify(&message_hash, &signature) {
        CRYPTO_SUCCESS
    } else {
        CRYPTO_ERROR_INVALID_PARAMETER
    }
}
