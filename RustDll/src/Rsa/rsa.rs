use num_bigint::{BigUint, BigInt, RandBigInt, ToBigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use std::io;
use std::str::FromStr;

pub struct RSA {
    n: BigUint,
    e: BigUint,
    d: Option<BigUint>,
}

impl RSA {
    /// 生成新的 Rsa 密钥对
    pub fn new(bit_length: usize) -> Self {
        // 生成两个大素数
        let p = generate_large_prime(bit_length);
        let q = generate_large_prime(bit_length);
        let n = &p * &q;

        // 计算欧拉函数 φ(n)
        let phi_n = (p - BigUint::one()) * (q - BigUint::one());

        // 选择公钥指数 e (这里先用 65537，后续有机会再改)
        let e = BigUint::from(65537u32);

        // 计算私钥指数 d (e 的模反元素)
        let d = mod_inverse(&e, &phi_n).expect("Failed to compute modular inverse");

        RSA { n, e, d: Some(d) }
    }

    /// 从公钥创建 Rsa 实例
    pub fn from_public_key(n: &str, e: &str) -> Self {
        RSA {
            n: BigUint::from_str(n).expect("Invalid n"),
            e: BigUint::from_str(e).expect("Invalid e"),
            d: None,
        }
    }

    /// 从私钥创建 Rsa 实例
    pub fn from_private_key(n: &str, d: &str) -> Self {
        RSA {
            n: BigUint::from_str(n).expect("Invalid n"),
            e: BigUint::zero(), // 私钥不需要 e
            d: Some(BigUint::from_str(d).expect("Invalid d")),
        }
    }

    /// 加密数据
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let m = BigUint::from_bytes_be(data);
        let c = m.modpow(&self.e, &self.n);
        c.to_bytes_be()
    }

    /// 解密数据
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let c = BigUint::from_bytes_be(data);
        let m = match &self.d {
            Some(d) => c.modpow(d, &self.n),
            None => panic!("Private key not available for decryption"),
        };
        m.to_bytes_be()
    }

    /// 获取公钥
    pub fn public_key(&self) -> (String, String) {
        (self.n.to_str_radix(10), self.e.to_str_radix(10))
    }

    /// 获取私钥
    pub fn private_key(&self) -> (String, String) {
        (
            self.n.to_str_radix(10),
            self.d.as_ref().unwrap().to_str_radix(10),
        )
    }
}

/// 生成指定位数的大素数
fn generate_large_prime(bit_length: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut candidate = rng.gen_biguint(bit_length as u64);

        // 确保是奇数
        if candidate.is_even() {
            candidate += BigUint::one();
        }

        // 确保位数正确
        if candidate.bits() < bit_length as u64 {
            candidate.set_bit((bit_length - 1) as u64, true);
        }

        // 使用概率性测试检查素数
        if is_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Miller-Rabin 素数测试
fn is_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n == &BigUint::from(2u8) || n == &BigUint::from(3u8) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // 将 n-1 分解为 d * 2^s
    let mut d = n - BigUint::one();
    let mut s = 0;
    while d.is_even() {
        d /= BigUint::from(2u8);
        s += 1;
    }

    let mut rng = OsRng;
    for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u8), &(n - BigUint::one()));
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n - BigUint::one() {
            continue;
        }

        let mut found = false;
        for _ in 0..s - 1 {
            x = x.modpow(&BigUint::from(2u8), n);
            if x == n - BigUint::one() {
                found = true;
                break;
            }
        }

        if !found {
            return false;
        }
    }

    true
}

/// 扩展欧几里得算法求模反元素
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let zero = BigInt::zero();
    let one = BigInt::one();

    let (mut old_r, mut r) = (a.to_bigint().unwrap(), m.to_bigint().unwrap());
    let (mut old_s, mut s) = (one.clone(), zero.clone());
    let (mut old_t, mut t) = (zero.clone(), one.clone());

    while !r.is_zero() {
        let quotient = &old_r / &r;

        let new_r = &old_r - &quotient * &r;
        old_r = r;
        r = new_r;

        let new_s = &old_s - &quotient * &s;
        old_s = s;
        s = new_s;

        let new_t = &old_t - &quotient * &t;
        old_t = t;
        t = new_t;
    }

    if old_r != one {
        return None; // 没有逆元
    }

    // 保证结果是正的 BigUint
    let result = if old_s < zero {
        old_s + m.to_bigint().unwrap()
    } else {
        old_s
    };

    result.to_biguint()
}


fn generate_and_use_keys() {
    println!("输入素数位数 (留空默认为1024):");
    let mut bit_length = String::new();
    io::stdin().read_line(&mut bit_length).expect("读取输入失败");

    let bit_length = match bit_length.trim() {
        "" => 1024,
        s => s.parse().expect("请输入有效数字"),
    };

    let rsa = RSA::new(bit_length);
    let (n, e) = rsa.public_key();
    let (_, d) = rsa.private_key();

    println!("\n公钥 (n, e):");
    println!("n = {}", n);
    println!("e = {}", e);

    println!("\n私钥 (n, d):");
    println!("n = {}", n);
    println!("d = {}", d);

    test_encryption_decryption(rsa);
}

fn encrypt_with_public_key() {
    println!("输入公钥 n:");
    let mut n = String::new();
    io::stdin().read_line(&mut n).expect("读取输入失败");

    println!("输入公钥 e:");
    let mut e = String::new();
    io::stdin().read_line(&mut e).expect("读取输入失败");

    let rsa = RSA::from_public_key(n.trim(), e.trim());

    println!("输入要加密的消息:");
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("读取输入失败");

    let encrypted = rsa.encrypt(message.trim().as_bytes());
    println!("\n加密结果 (十六进制): {}", hex::encode(&encrypted));
}

fn decrypt_with_private_key() {
    println!("输入私钥 n:");
    let mut n = String::new();
    io::stdin().read_line(&mut n).expect("读取输入失败");

    println!("输入私钥 d:");
    let mut d = String::new();
    io::stdin().read_line(&mut d).expect("读取输入失败");

    let rsa = RSA::from_private_key(n.trim(), d.trim());

    println!("输入要解密的密文 (十六进制):");
    let mut ciphertext = String::new();
    io::stdin().read_line(&mut ciphertext).expect("读取输入失败");

    let ciphertext_bytes = hex::decode(ciphertext.trim()).expect("无效的十六进制");
    let decrypted = rsa.decrypt(&ciphertext_bytes);

    match String::from_utf8(decrypted) {
        Ok(s) => println!("\n解密结果: {}", s),
        Err(_) => println!("\n解密结果不是有效 UTF-8 字符串"),
    }
}

fn test_encryption_decryption(rsa: RSA) {
    println!("\n输入测试消息:");
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("读取输入失败");
    let message = message.trim();

    println!("\n原始消息: {}", message);

    // 加密
    let encrypted = rsa.encrypt(message.as_bytes());
    println!("加密结果 (十六进制): {}", hex::encode(&encrypted));

    // 解密
    let decrypted = rsa.decrypt(&encrypted);
    let decrypted_str = String::from_utf8(decrypted).expect("解密结果不是有效 UTF-8");
    println!("解密结果: {}", decrypted_str);

    // 验证
    if message == decrypted_str {
        println!("验证成功: 原始消息与解密消息一致");
    } else {
        println!("验证失败: 原始消息与解密消息不一致");
    }
}