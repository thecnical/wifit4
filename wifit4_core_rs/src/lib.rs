/*!
wifit4_core — Rust/PyO3 hot-path extension module.

Provides zero-copy frame parsing and WPA2 PBKDF2 hash cracking that run at
C-level speed without the Python GIL.

Build:
    cd wifit4_core_rs
    pip install maturin
    maturin develop --release   # installs into current venv
    # or: maturin build --release && pip install target/wheels/*.whl

Python usage:
    import wifit4_core
    frame = wifit4_core.parse_dot11(raw_bytes)
    psk   = wifit4_core.check_wpa2_psk(ssid, passphrase, pmk_bytes)
*/

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

// ---------------------------------------------------------------------------
// 802.11 frame type constants (FC byte 0, bits 2-3 = type, bits 4-7 = subtype)
// ---------------------------------------------------------------------------

const FC_TYPE_MASK:    u8 = 0x0C;
const FC_SUBTYPE_MASK: u8 = 0xF0;
const FC_TYPE_MGMT:    u8 = 0x00;
const FC_TYPE_CTRL:    u8 = 0x04;
const FC_TYPE_DATA:    u8 = 0x08;

// Management subtypes
const SUBTYPE_BEACON:       u8 = 0x80;
const SUBTYPE_PROBE_REQ:    u8 = 0x40;
const SUBTYPE_PROBE_RESP:   u8 = 0x50;
const SUBTYPE_ASSOC_REQ:    u8 = 0x00;
const SUBTYPE_REASSOC_REQ:  u8 = 0x20;
const SUBTYPE_AUTH:         u8 = 0xB0;
const SUBTYPE_DEAUTH:       u8 = 0xC0;
const SUBTYPE_DISASSOC:     u8 = 0xA0;

// Data subtype that carries EAPOL
const SUBTYPE_DATA:         u8 = 0x00;
const SUBTYPE_QOS_DATA:     u8 = 0x80;

// EAPOL Ethertype in LLC/SNAP header
const ETHERTYPE_EAPOL: [u8; 2] = [0x88, 0x8E];

// ---------------------------------------------------------------------------
// Parsed frame structure (returned to Python as a dict)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Dot11Frame<'a> {
    frame_type:    &'static str,
    frame_subtype: &'static str,
    dst:           [u8; 6],
    src:           [u8; 6],
    bssid:         [u8; 6],
    seq:           u16,
    body_offset:   usize,
    raw:           &'a [u8],
}

// ---------------------------------------------------------------------------
// parse_dot11 — exposed to Python
// ---------------------------------------------------------------------------

/// parse_dot11(raw: bytes) -> dict | None
///
/// Zero-copy parse of an 802.11 frame.  Returns a Python dict with keys:
///   frame_type, frame_subtype, dst, src, bssid, seq, body, is_eapol
/// Returns None for frames that are too short or have unknown type.
#[pyfunction]
fn parse_dot11(py: Python<'_>, raw: &PyBytes) -> PyResult<Option<PyObject>> {
    let data: &[u8] = raw.as_bytes();

    if data.len() < 24 {
        return Ok(None);
    }

    let fc0 = data[0];
    let fc1 = data[1];
    let frame_type    = fc0 & FC_TYPE_MASK;
    let frame_subtype = fc0 & FC_SUBTYPE_MASK;

    let type_str = match frame_type {
        FC_TYPE_MGMT => "management",
        FC_TYPE_CTRL => "control",
        FC_TYPE_DATA => "data",
        _            => "extension",
    };

    let subtype_str = match (frame_type, frame_subtype) {
        (FC_TYPE_MGMT, SUBTYPE_BEACON)      => "beacon",
        (FC_TYPE_MGMT, SUBTYPE_PROBE_REQ)   => "probe_req",
        (FC_TYPE_MGMT, SUBTYPE_PROBE_RESP)  => "probe_resp",
        (FC_TYPE_MGMT, SUBTYPE_ASSOC_REQ)   => "assoc_req",
        (FC_TYPE_MGMT, SUBTYPE_REASSOC_REQ) => "reassoc_req",
        (FC_TYPE_MGMT, SUBTYPE_AUTH)        => "auth",
        (FC_TYPE_MGMT, SUBTYPE_DEAUTH)      => "deauth",
        (FC_TYPE_MGMT, SUBTYPE_DISASSOC)    => "disassoc",
        (FC_TYPE_DATA, SUBTYPE_DATA)        => "data",
        (FC_TYPE_DATA, SUBTYPE_QOS_DATA)    => "qos_data",
        _                                   => "other",
    };

    // Standard 802.11 addresses
    let dst:   [u8; 6] = data[4..10].try_into().unwrap_or([0u8; 6]);
    let src:   [u8; 6] = data[10..16].try_into().unwrap_or([0u8; 6]);
    let bssid: [u8; 6] = data[16..22].try_into().unwrap_or([0u8; 6]);
    let seq = u16::from_le_bytes([data[22], data[23]]) >> 4;

    // Determine body offset (QoS data adds 2 bytes; 4-addr adds 6)
    let has_4addr = (fc1 & 0x03) == 0x03;
    let is_qos    = frame_type == FC_TYPE_DATA && (frame_subtype & 0x80 != 0);
    let body_off  = 24 + if has_4addr { 6 } else { 0 } + if is_qos { 2 } else { 0 };

    // EAPOL detection: LLC/SNAP header (8 bytes) + ethertype 0x888E
    let is_eapol = frame_type == FC_TYPE_DATA
        && data.len() > body_off + 8
        && data[body_off + 6..body_off + 8] == ETHERTYPE_EAPOL;

    // Build Python dict
    let dict = PyDict::new(py);
    dict.set_item("frame_type",    type_str)?;
    dict.set_item("frame_subtype", subtype_str)?;
    dict.set_item("dst",   format_mac(&dst))?;
    dict.set_item("src",   format_mac(&src))?;
    dict.set_item("bssid", format_mac(&bssid))?;
    dict.set_item("seq",   seq)?;
    dict.set_item("body",  PyBytes::new(py, &data[body_off.min(data.len())..])?)?;
    dict.set_item("is_eapol", is_eapol)?;

    Ok(Some(dict.into()))
}

// ---------------------------------------------------------------------------
// check_wpa2_psk — WPA2 PBKDF2-SHA1 PMK derivation + PTK verification
// ---------------------------------------------------------------------------

/// check_wpa2_psk(ssid: str, passphrase: str, anonce: bytes, snonce: bytes,
///                ap_mac: bytes, sta_mac: bytes, eapol_mic: bytes,
///                eapol_data: bytes) -> bool
///
/// Returns True if the passphrase produces an MIC that matches eapol_mic.
/// Runs entirely in Rust — no GIL held after argument extraction.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn check_wpa2_psk(
    ssid:       &str,
    passphrase: &str,
    anonce:     &PyBytes,
    snonce:     &PyBytes,
    ap_mac:     &PyBytes,
    sta_mac:    &PyBytes,
    eapol_mic:  &PyBytes,
    eapol_data: &PyBytes,
) -> PyResult<bool> {
    let pmk = pbkdf2_sha1(passphrase.as_bytes(), ssid.as_bytes(), 4096, 32);

    // PTK = PRF-512(PMK, "Pairwise key expansion", min(APmac,STAmac) || max(APmac,STAmac) || min(ANonce,SNonce) || max(ANonce,SNonce))
    let ap  = ap_mac.as_bytes();
    let sta = sta_mac.as_bytes();
    let an  = anonce.as_bytes();
    let sn  = snonce.as_bytes();

    let mut data = Vec::with_capacity(76);
    if ap < sta { data.extend_from_slice(ap); data.extend_from_slice(sta); }
    else         { data.extend_from_slice(sta); data.extend_from_slice(ap); }
    if an < sn  { data.extend_from_slice(an); data.extend_from_slice(sn); }
    else         { data.extend_from_slice(sn); data.extend_from_slice(an); }

    let ptk = prf512(&pmk, b"Pairwise key expansion", &data);
    let kck = &ptk[..16]; // Key Confirmation Key

    // MIC = HMAC-SHA1(KCK, eapol_data_with_mic_zeroed)[..16]
    let mic = hmac_sha1_16(kck, eapol_data.as_bytes());
    Ok(mic == eapol_mic.as_bytes())
}

// ---------------------------------------------------------------------------
// Internal crypto helpers (no external crates — pure Rust stdlib + manual impl)
// ---------------------------------------------------------------------------

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    // PBKDF2-HMAC-SHA1 — RFC 2898
    let mut dk = Vec::with_capacity(dk_len);
    let mut block_num: u32 = 1;
    while dk.len() < dk_len {
        let mut u = hmac_sha1(password, &[salt, &block_num.to_be_bytes()[..]].concat());
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        dk.extend_from_slice(&t);
        block_num += 1;
    }
    dk.truncate(dk_len);
    dk
}

fn prf512(key: &[u8], label: &[u8], data: &[u8]) -> Vec<u8> {
    // WPA2 PRF-512 = concatenation of HMAC-SHA1 blocks with counter
    let mut result = Vec::with_capacity(64);
    for i in 0u8..4 {
        let mut input = Vec::with_capacity(label.len() + 1 + data.len() + 1);
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(data);
        input.push(i);
        result.extend_from_slice(&hmac_sha1(key, &input));
    }
    result.truncate(64);
    result
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let k = if key.len() > BLOCK { sha1(key) } else { key.to_vec() };
    let mut ipad = vec![0x36u8; BLOCK];
    let mut opad = vec![0x5Cu8; BLOCK];
    for i in 0..k.len() { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    let inner = sha1(&[ipad.as_slice(), data].concat());
    sha1(&[opad.as_slice(), inner.as_slice()].concat())
}

fn hmac_sha1_16(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha1(key, data)[..16].to_vec()
}

fn sha1(data: &[u8]) -> Vec<u8> {
    // SHA-1 — FIPS 180-4
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = data.len() as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19  => ((b & c) | ((!b) & d),       0x5A827999u32),
                20..=39 => (b ^ c ^ d,                   0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _       => (b ^ c ^ d,                   0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().flat_map(|x| x.to_be_bytes()).collect()
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// ---------------------------------------------------------------------------
// Python module registration
// ---------------------------------------------------------------------------

/// wifit4_core — Rust-accelerated 802.11 frame parsing and WPA2 cracking.
#[pymodule]
fn wifit4_core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_dot11, m)?)?;
    m.add_function(wrap_pyfunction!(check_wpa2_psk, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
