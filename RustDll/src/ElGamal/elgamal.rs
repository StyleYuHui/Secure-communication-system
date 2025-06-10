use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256}; // 新增
use std::io;
use std::str::FromStr;

// 定义 ElGamal 密钥结构
pub struct ElGamalKeys {
    p: BigUint,
    g: BigUint,
    y: BigUint,
    x: BigUint,
}

// ElGamal 加密结果
pub struct ElGamalCiphertext {
    pub(crate) c1: BigUint,
    pub(crate) c2: BigUint,
}

// ElGamal 签名
pub struct ElGamalSignature {
    pub(crate) r: BigUint,
    pub(crate) s: BigUint,
}

impl ElGamalKeys {
    pub fn new(bit_length: usize) -> Self {
        let p = generate_safe_prime(bit_length);
        let q = (&p - BigUint::one()) / BigUint::from(2u32);
        let g = find_generator(&p, &q);

        let mut rng = OsRng;
        let x = rng.gen_biguint_range(&BigUint::one(), &q);
        let y = g.modpow(&x, &p);

        ElGamalKeys { p, g, y, x }
    }

    pub fn from_params(p: &str, g: &str, y: &str, x: &str) -> Self {
        ElGamalKeys {
            p: BigUint::from_str(p).expect("Invalid p"),
            g: BigUint::from_str(g).expect("Invalid g"),
            y: BigUint::from_str(y).expect("Invalid y"),
            x: BigUint::from_str(x).expect("Invalid x"),
        }
    }

    pub fn from_public_params(p: &str, g: &str, y: &str) -> Self {
        ElGamalKeys {
            p: BigUint::from_str(p).expect("Invalid p"),
            g: BigUint::from_str(g).expect("Invalid g"),
            y: BigUint::from_str(y).expect("Invalid y"),
            x: BigUint::zero(),
        }
    }

    pub fn from_private_params(p: &str, g: &str, x: &str) -> Self {
        let p_big = BigUint::from_str(p).expect("Invalid p");
        let g_big = BigUint::from_str(g).expect("Invalid g");
        let x_big = BigUint::from_str(x).expect("Invalid x");
        let y = g_big.modpow(&x_big, &p_big);

        ElGamalKeys {
            p: p_big,
            g: g_big,
            y,
            x: x_big,
        }
    }

    pub fn public_key(&self) -> (String, String, String) {
        (
            self.p.to_str_radix(10),
            self.g.to_str_radix(10),
            self.y.to_str_radix(10),
        )
    }

    pub fn private_key(&self) -> (String, String, String) {
        (
            self.p.to_str_radix(10),
            self.g.to_str_radix(10),
            self.x.to_str_radix(10),
        )
    }

    pub fn encrypt(&self, message: &BigUint) -> ElGamalCiphertext {
        let mut rng = OsRng;
        let k = rng.gen_biguint_range(&BigUint::one(), &(&self.p - BigUint::one()));
        let c1 = self.g.modpow(&k, &self.p);
        let c2 = (message * self.y.modpow(&k, &self.p)) % &self.p;

        ElGamalCiphertext { c1, c2 }
    }

    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> BigUint {
        let s = ciphertext.c1.modpow(&self.x, &self.p);
        let s_inv = mod_inverse(&s, &self.p).expect("Failed to compute modular inverse");
        (&ciphertext.c2 * s_inv) % &self.p
    }

    pub fn sign(&self, message: &BigUint) -> ElGamalSignature {
        let mut rng = OsRng;
        let q = (&self.p - BigUint::one()) / BigUint::from(2u32);

        loop {
            let k = rng.gen_biguint_range(&BigUint::one(), &q);
            let r = self.g.modpow(&k, &self.p);

            if let Some(k_inv) = mod_inverse(&k, &q) {
                let m_mod_q = message % &q;
                let s = ((&m_mod_q + &q - (&self.x * &r) % &q) * k_inv) % &q;
                return ElGamalSignature { r, s };
            }
        }
    }

    pub fn verify(&self, message: &BigUint, signature: &ElGamalSignature) -> bool {
        if signature.r <= BigUint::zero() || signature.r >= self.p {
            return false;
        }

        let q = (&self.p - BigUint::one()) / BigUint::from(2u32);

        if signature.s <= BigUint::zero() || signature.s >= q {
            return false;
        }

        let v1 = self.g.modpow(message, &self.p);
        let v2 = (self.y.modpow(&signature.r, &self.p)
            * signature.r.modpow(&signature.s, &self.p))
            % &self.p;

        v1 == v2
    }
}

fn generate_safe_prime(bit_length: usize) -> BigUint {
    let mut rng = OsRng;
    let mut candidate: BigUint;

    loop {
        candidate = rng.gen_biguint(bit_length as u64);
        if candidate.is_even() {
            candidate += BigUint::one();
        }
        if candidate.bits() < bit_length as u64 {
            candidate.set_bit((bit_length - 1) as u64, true);
        }

        let p = &candidate * BigUint::from(2u32) + BigUint::one();

        if is_prime(&candidate, 20) && is_prime(&p, 20) {
            return p;
        }
    }
}

fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
    let mut rng = OsRng;
    let mut candidate: BigUint;

    loop {
        candidate = rng.gen_biguint_range(&BigUint::from(2u32), &(p - BigUint::from(2u32)));

        // 修正: g^q mod p ≠ 1
        if candidate.modpow(q, p) == BigUint::one() {
            continue;
        }

        return candidate;
    }
}

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

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a = a.to_bigint().unwrap();
    let m = m.to_bigint().unwrap();

    let (mut old_r, mut r) = (a.clone(), m.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));

    while r != BigInt::from(0) {
        let quotient = &old_r / &r;

        let new_r = &old_r - &quotient * &r;
        old_r = r;
        r = new_r;

        let new_s = &old_s - &quotient * &s;
        old_s = s;
        s = new_s;
    }

    if old_r != BigInt::from(1) {
        return None;
    }

    let result = if old_s < BigInt::from(0) {
        old_s + m
    } else {
        old_s
    };

    Some(result.to_biguint().unwrap())
}

// SHA256 -> BigUint
pub fn sha256_to_biguint(input: &str) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    BigUint::from_bytes_be(&hash)
}

fn generate_keys() {
    println!("输入素数位数 (留空默认为256):");
    let mut bit_length = String::new();
    io::stdin().read_line(&mut bit_length).expect("读取输入失败");

    let bit_length = match bit_length.trim() {
        "" => 256,
        s => s.parse().expect("请输入有效数字"),
    };

    if bit_length < 64 {
        println!("警告：位数太小，安全性不足！");
    }

    println!("正在生成安全素数，请稍候...");
    let elgamal = ElGamalKeys::new(bit_length);
    let (p, g, y) = elgamal.public_key();
    let (_, _, x) = elgamal.private_key();

    println!("\n公钥参数 (p, g, y):");
    println!("p = {}", p);
    println!("g = {}", g);
    println!("y = {}", y);

    println!("\n私钥参数 (p, g, x):");
    println!("p = {}", p);
    println!("g = {}", g);
    println!("x = {}", x);
}

fn encrypt_message() {
    println!("输入公钥参数 p:");
    let mut p = String::new();
    io::stdin().read_line(&mut p).expect("读取输入失败");

    println!("输入公钥参数 g:");
    let mut g = String::new();
    io::stdin().read_line(&mut g).expect("读取输入失败");

    println!("输入公钥参数 y:");
    let mut y = String::new();
    io::stdin().read_line(&mut y).expect("读取输入失败");

    let elgamal = ElGamalKeys::from_public_params(p.trim(), g.trim(), y.trim());

    println!("输入要加密的消息 (数字 <= p-1):");
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("读取输入失败");

    let m = BigUint::from_str(message.trim()).expect("无效的数字");
    let ciphertext = elgamal.encrypt(&m);

    println!("\n加密结果:");
    println!("c1 = {}", ciphertext.c1);
    println!("c2 = {}", ciphertext.c2);
}

fn decrypt_message() {
    println!("输入私钥参数 p:");
    let mut p = String::new();
    io::stdin().read_line(&mut p).expect("读取输入失败");

    println!("输入私钥参数 g:");
    let mut g = String::new();
    io::stdin().read_line(&mut g).expect("读取输入失败");

    println!("输入私钥参数 x:");
    let mut x = String::new();
    io::stdin().read_line(&mut x).expect("读取输入失败");

    let elgamal = ElGamalKeys::from_private_params(p.trim(), g.trim(), x.trim());

    println!("输入要解密的 c1:");
    let mut c1 = String::new();
    io::stdin().read_line(&mut c1).expect("读取输入失败");

    println!("输入要解密的 c2:");
    let mut c2 = String::new();
    io::stdin().read_line(&mut c2).expect("读取输入失败");

    let ciphertext = ElGamalCiphertext {
        c1: BigUint::from_str(c1.trim()).expect("无效的 c1"),
        c2: BigUint::from_str(c2.trim()).expect("无效的 c2"),
    };

    let decrypted = elgamal.decrypt(&ciphertext);

    println!("\n解密得到消息: {}", decrypted);
}

fn sign_message() {
    println!("输入私钥参数 p:");
    let mut p = String::new();
    io::stdin().read_line(&mut p).expect("读取输入失败");

    println!("输入私钥参数 g:");
    let mut g = String::new();
    io::stdin().read_line(&mut g).expect("读取输入失败");

    println!("输入私钥参数 x:");
    let mut x = String::new();
    io::stdin().read_line(&mut x).expect("读取输入失败");

    let elgamal = ElGamalKeys::from_private_params(p.trim(), g.trim(), x.trim());

    println!("输入要签名的消息 (字符串):");
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("读取输入失败");

    let hashed_m = sha256_to_biguint(message.trim());
    let signature = elgamal.sign(&hashed_m);

    println!("\n签名结果:");
    println!("r = {}", signature.r);
    println!("s = {}", signature.s);
}

fn verify_signature() {
    println!("输入公钥参数 p:");
    let mut p = String::new();
    io::stdin().read_line(&mut p).expect("读取输入失败");

    println!("输入公钥参数 g:");
    let mut g = String::new();
    io::stdin().read_line(&mut g).expect("读取输入失败");

    println!("输入公钥参数 y:");
    let mut y = String::new();
    io::stdin().read_line(&mut y).expect("读取输入失败");

    let elgamal = ElGamalKeys::from_public_params(p.trim(), g.trim(), y.trim());

    println!("输入被签名的消息 (字符串):");
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("读取输入失败");

    println!("输入签名 r:");
    let mut r = String::new();
    io::stdin().read_line(&mut r).expect("读取输入失败");

    println!("输入签名 s:");
    let mut s = String::new();
    io::stdin().read_line(&mut s).expect("读取输入失败");

    let signature = ElGamalSignature {
        r: BigUint::from_str(r.trim()).expect("无效的 r"),
        s: BigUint::from_str(s.trim()).expect("无效的 s"),
    };

    let hashed_m = sha256_to_biguint(message.trim());
    let valid = elgamal.verify(&hashed_m, &signature);

    if valid {
        println!("签名验证成功！");
    } else {
        println!("签名验证失败！");
    }
}
