# ECHConfig Decoder - Bug Research Report

**Date:** 2025-11-23
**Repository:** cowsay/echconfig
**Analyzed Files:** app.js (979 lines), index.html (107 lines), style.css (297 lines)

## Executive Summary

This report documents potential bugs, security concerns, and edge cases discovered during a comprehensive code review of the ECHConfig Decoder application. Issues are categorized by severity: **Critical**, **High**, **Medium**, and **Low**.

**Total Issues Found:** 13

---

## Critical Severity Issues

### 1. Stack Overflow in `uint8ToBase64` with Large Arrays
**Location:** `app.js:36`
**Severity:** Critical
**Type:** Memory/Performance

```javascript
const uint8ToBase64 = (uint8Array) => {
    return btoa(String.fromCharCode(...uint8Array)); // ❌ Spread operator
};
```

**Problem:**
- The spread operator `...uint8Array` expands the entire array as function arguments
- JavaScript has a maximum call stack size (typically ~65,000-100,000 arguments in most browsers)
- An ECH config near the 8KB limit would have ~8,000 bytes, well within current limits
- However, if `ECH_MAX_SIZE` is ever increased, this will cause `RangeError: Maximum call stack size exceeded`

**Proof of Concept:**
```javascript
const largeArray = new Uint8Array(200000); // Exceeds stack
uint8ToBase64(largeArray); // ❌ RangeError
```

**Impact:**
- Application crash on large valid inputs
- Poor user experience

**Recommendation:**
Use chunked processing:
```javascript
const uint8ToBase64 = (uint8Array) => {
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < uint8Array.length; i += chunkSize) {
        const chunk = uint8Array.subarray(i, i + chunkSize);
        binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
};
```

---

## High Severity Issues

### 2. Input Size Validation on String Length Instead of Decoded Bytes
**Location:** `app.js:279-281`
**Severity:** High
**Type:** Logic Error / DoS Vector

```javascript
if (cleaned.length > ECH_MAX_SIZE) {
    throw new Error(`Input too large...`);
}
```

**Problem:**
- Validates the **string length** of input, not the **decoded byte length**
- A base64 string is ~33% larger than the decoded data (4 chars = 3 bytes)
- A hex string is 200% larger than decoded data (2 chars = 1 byte)
- An attacker could bypass the check with a hex string of 16,384 characters that decodes to 8,192 bytes

**Examples:**
- Base64 string of 10,000 chars → ~7,500 bytes (passes check, valid)
- Hex string of 10,000 chars → 5,000 bytes (passes check, valid)
- Hex string of 16,000 chars → 8,000 bytes (passes check, exceeds intent)

**Impact:**
- Size limits can be bypassed
- Could lead to excessive memory usage
- Validation happens after expensive decoding operations

**Recommendation:**
Move size validation to after decoding:
```javascript
const result = detectAndDecodeSingle(cleaned);
if (result.data.length > ECH_MAX_SIZE) {
    throw new Error(`Decoded data too large...`);
}
```

---

### 3. Missing Bounds Checking in Cloudflare DNS Wire Format Parser
**Location:** `app.js:946-953`
**Severity:** High
**Type:** Buffer Overflow / Crash Risk

```javascript
while (i < bytes.length && bytes[i] !== 0) {
    const labelLen = bytes[i];
    if (labelLen === 0) break;
    i += 1 + labelLen; // ❌ No validation that we have labelLen bytes
}
```

**Problem:**
- Reads `labelLen` from the wire format but doesn't validate that `i + 1 + labelLen` is within bounds
- If DNS response is malformed or malicious, could read past array end
- Example: `bytes = [5, 'h', 'e', 'l']` → `labelLen=5` but only 3 chars available

**Proof of Concept:**
```javascript
const malformed = new Uint8Array([0, 0, 10, 'a', 'b']); // Label claims 10 bytes, only 2 present
// Loop would set i = 3 + 10 = 13, skipping validation
```

**Impact:**
- Reading undefined array elements (returns `undefined` in JS, but logic breaks)
- Parser produces incorrect results
- Potential for exploitation if responses are manipulated

**Recommendation:**
```javascript
while (i < bytes.length && bytes[i] !== 0) {
    const labelLen = bytes[i];
    if (labelLen === 0) break;
    if (i + 1 + labelLen > bytes.length) {
        throw new Error('Malformed DNS wire format: label extends beyond data');
    }
    i += 1 + labelLen;
}
```

---

### 4. Missing Bounds Checking in Cloudflare Parameter Parsing
**Location:** `app.js:955-969`
**Severity:** High
**Type:** Buffer Overflow / Crash Risk

```javascript
while (i < bytes.length - 3) { // ❌ Only ensures 4 bytes for key+len
    const key = (bytes[i] << 8) | bytes[i + 1];
    const len = (bytes[i + 2] << 8) | bytes[i + 3];

    if (key === 5 && i + 4 + len <= bytes.length) { // ✓ Good check here
        const echBytes = bytes.slice(i + 4, i + 4 + len);
        // ...
        break;
    }

    i += 4 + len; // ❌ Could advance beyond array if len is malicious
}
```

**Problem:**
- Loop condition ensures 4 bytes exist for key/len
- But doesn't validate that `len` bytes actually exist before advancing `i += 4 + len`
- Only the ECH key (5) has bounds checking; other keys could cause out-of-bounds access

**Scenario:**
```javascript
// bytes = [0, 1, 0, 10, ...only 2 bytes remaining...]
// key=1, len=10, but only 2 bytes left
// i += 4 + 10 = 14, loop continues with i out of bounds
```

**Impact:**
- Infinite loop or premature termination
- Incorrect parsing of valid data

**Recommendation:**
```javascript
while (i < bytes.length - 3) {
    const key = (bytes[i] << 8) | bytes[i + 1];
    const len = (bytes[i + 2] << 8) | bytes[i + 3];

    if (i + 4 + len > bytes.length) {
        throw new Error('Malformed HTTPS record: parameter extends beyond data');
    }

    if (key === 5) {
        const echBytes = bytes.slice(i + 4, i + 4 + len);
        echConfigs.push({ base64: uint8ToBase64(echBytes), record: data });
        break;
    }

    i += 4 + len;
}
```

---

## Medium Severity Issues

### 5. Missing Validation in `readVarBytes` Length Parameter
**Location:** `app.js:146-149`
**Severity:** Medium
**Type:** Logic Error

```javascript
readVarBytes(lengthBytes = 2) {
    const length = lengthBytes === 1 ? this.readUint8() : this.readUint16();
    return this.readBytes(length);
}
```

**Problem:**
- Only handles `lengthBytes === 1` or `lengthBytes === 2`
- If called with any other value (0, 3, 4, etc.), falls back to `readUint16()` silently
- No validation or error thrown for invalid parameter

**Impact:**
- Silent bugs if method is called incorrectly
- Difficult to debug

**Recommendation:**
```javascript
readVarBytes(lengthBytes = 2) {
    if (lengthBytes !== 1 && lengthBytes !== 2) {
        throw new Error(`Invalid lengthBytes parameter: ${lengthBytes} (must be 1 or 2)`);
    }
    const length = lengthBytes === 1 ? this.readUint8() : this.readUint16();
    return this.readBytes(length);
}
```

---

### 6. Silent Truncation of Malformed Cipher Suites
**Location:** `app.js:239-244`
**Severity:** Medium
**Type:** Data Integrity

```javascript
while (suitesReader.hasBytes(4)) {
    contents.key_config.cipher_suites.push({
        kdf: suitesReader.readUint16(),
        aead: suitesReader.readUint16()
    });
}
// If 1-3 bytes remain, they're silently ignored
```

**Problem:**
- If `suitesBytes` length is not a multiple of 4, leftover bytes (1-3) are silently discarded
- This could indicate a corrupted or malformed ECH config
- User has no indication that data was incomplete

**Example:**
```javascript
// Cipher suites length: 10 bytes
// Parses: 2 complete suites (8 bytes)
// Ignores: 2 remaining bytes (should be detected as corruption)
```

**Impact:**
- Corrupted data appears valid
- Users may not notice incomplete parsing

**Recommendation:**
```javascript
while (suitesReader.hasBytes(4)) {
    contents.key_config.cipher_suites.push({
        kdf: suitesReader.readUint16(),
        aead: suitesReader.readUint16()
    });
}

if (suitesReader.remaining() > 0) {
    throw new Error(`Malformed cipher_suites: ${suitesReader.remaining()} unexpected bytes remaining`);
}
```

---

### 7. Silent Truncation of Malformed Extensions
**Location:** `app.js:259-267`
**Severity:** Medium
**Type:** Data Integrity (same as #6)

```javascript
while (extensionsReader.hasBytes(4)) {
    const type = extensionsReader.readUint16();
    const data = extensionsReader.readVarBytes(2);
    contents.extensions.push({ type, len: data.length, hex: toHexBytes(data, '') });
}
// Leftover bytes silently ignored
```

**Problem:** Same as issue #6, but for extensions parsing.

**Recommendation:** Same validation as #6.

---

### 8. Incomplete Regex for DNS HTTPS Record `ech=` Parameter
**Location:** `app.js:319-322`
**Severity:** Medium
**Type:** Parsing Error

```javascript
const echMatch = cleaned.match(/\bech=["']?([A-Za-z0-9+/=]+)["']?/i);
```

**Problem:**
- Missing URL-safe base64 characters: `-` and `_`
- RFC 4648 defines URL-safe base64 as using `-` and `_` instead of `+` and `/`
- Some DNS records may use URL-safe encoding

**Impact:**
- Fails to parse valid ECH parameters using URL-safe base64
- Truncates at first `-` or `_` character

**Example:**
```javascript
"ech=AQM-_ABC" // Only matches "AQM", stops at '-'
```

**Recommendation:**
```javascript
const echMatch = cleaned.match(/\bech=["']?([A-Za-z0-9+/=_-]+)["']?/i);
```

---

### 9. Weak File Type Detection Heuristic
**Location:** `app.js:483`
**Severity:** Medium
**Type:** Logic Error

```javascript
const isProbablyText = rawBytes.length > 0 &&
                       rawBytes[0] >= ASCII_PRINTABLE_START &&
                       rawBytes[0] <= ASCII_PRINTABLE_END;
```

**Problem:**
- Only checks the **first byte** to determine if file is text or binary
- Many binary files start with printable ASCII (e.g., JPEG: `0xFF`, PNG: `0x89`, PDF: `0x25` = '%')
- ELF binaries start with `0x7F` (DEL, just outside printable range)

**Impact:**
- Binary files may be incorrectly decoded as text
- Text files with non-ASCII first character (BOM, UTF-8) may be treated as binary

**Example:**
```javascript
// PDF file: starts with '%PDF' (0x25 = '%', printable)
// Would be decoded as text, fail Base64 decoding, fall back to binary (works by accident)
```

**Recommendation:**
Use more robust detection:
```javascript
const isProbablyText = (rawBytes) => {
    if (rawBytes.length === 0) return false;

    // Check for common binary signatures
    if (rawBytes.length >= 2) {
        const signature = (rawBytes[0] << 8) | rawBytes[1];
        if (signature === 0xFEFF || signature === 0xFFFE) return true; // BOM
        if (signature === 0xFE0D || signature === 0xFE0E) return false; // ECH version
    }

    // Check first 100 bytes for printability
    const sampleSize = Math.min(100, rawBytes.length);
    let printableCount = 0;
    for (let i = 0; i < sampleSize; i++) {
        const byte = rawBytes[i];
        if ((byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D) {
            printableCount++;
        }
    }
    return printableCount / sampleSize > 0.85; // 85% printable = probably text
};
```

---

### 10. Potential Edge Case in Domain Extraction from URL
**Location:** `app.js:683-684`
**Severity:** Low-Medium
**Type:** Edge Case

```javascript
} else if (input.includes('/')) {
    domain = input.split('/')[0];
}
```

**Problem:**
- If input is exactly `/`, `split('/')[0]` returns empty string
- If input is `//example.com`, `split('/')[0]` returns empty string
- These edge cases may not be user-facing but indicate defensive programming gap

**Impact:**
- Empty domain would be caught by `validateDomainName`, but error message would be confusing

**Recommendation:**
```javascript
} else if (input.includes('/')) {
    const parts = input.split('/').filter(p => p.length > 0);
    domain = parts.length > 0 ? parts[0] : input;
}
```

---

## Low Severity Issues

### 11. Inconsistent Minimum Size Validation
**Location:** `app.js:57-59` vs `app.js:220-270`
**Severity:** Low
**Type:** Documentation/Consistency

```javascript
const ECH_MIN_SIZE = 10; // Line 1

// validateECHData checks for 10 bytes minimum
if (uint8Array.length < ECH_MIN_SIZE) { ... } // Line 58

// parseECHConfigContents actually requires:
// 1 (config_id) + 2 (kem_id) + 2 (public_key len) + 0 (public_key)
// + 2 (cipher_suites len) + 0 (cipher_suites)
// + 1 (max_name_len) + 1 (public_name len) + 0 (public_name)
// + 2 (extensions len) = 11 bytes minimum
```

**Problem:**
- `ECH_MIN_SIZE = 10` is actually 1 byte too small for the minimum parseable config
- Configs with exactly 10 bytes will pass validation but fail parsing
- Not critical because errors are caught and displayed gracefully

**Impact:**
- Confusing error messages for 10-byte inputs

**Recommendation:**
Change to `const ECH_MIN_SIZE = 11;` and update error message.

---

### 12. Overly Permissive Hex Detection
**Location:** `app.js:330-335`
**Severity:** Low
**Type:** False Positive Risk

```javascript
if (/^[0-9a-fA-F\s]+$/.test(cleaned)) {
    const hexOnly = cleaned.replace(/\s+/g, '');
    if (hexOnly.length >= MIN_HEX_LENGTH) {
        return { data: hexToUint8(cleaned), format: 'Hex' };
    }
}
```

**Problem:**
- Any string containing only hex digits and whitespace is treated as hex
- Could misinterpret user input that happens to be all hex-like
- Example: `"CAFE BABE DEAD BEEF"` would be parsed as hex, not searched for `ech=` parameter

**Impact:**
- Unlikely to cause issues in practice since validation happens later
- Could lead to confusing error messages

**Recommendation:**
Require a minimum length (already has `MIN_HEX_LENGTH = 4`) or look for patterns like prefixes (`0x`).

---

### 13. No CSP (Content Security Policy) Headers
**Location:** `index.html` (missing meta tag)
**Severity:** Low
**Type:** Security Best Practice

**Problem:**
- No Content Security Policy defined
- While this is a client-side only app with no user-generated content rendering, CSP is still best practice
- Protects against potential XSS if code is ever modified

**Impact:**
- Currently minimal since all content is safely constructed via DOM APIs
- Future modifications could introduce XSS risks

**Recommendation:**
Add CSP meta tag to `index.html`:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src https://dns.google https://cloudflare-dns.com;">
```

---

## Positive Security Findings

✅ **No use of dangerous APIs**: No `eval()`, `innerHTML`, `document.write()`
✅ **DOM manipulation via safe methods**: Uses `createElement()`, `textContent`, `appendChild()`
✅ **Input validation**: Size limits enforced
✅ **Error handling**: Comprehensive try-catch blocks throughout
✅ **Bounds checking in BinaryReader**: All read methods check remaining bytes
✅ **UTF-8 validation**: Uses `TextDecoder` with `fatal: true` for public_name
✅ **No external dependencies**: Reduces supply chain risk
✅ **Client-side processing**: No data sent to servers (except optional DNS queries)

---

## Recommendations Summary

### Immediate Actions (Critical/High)
1. **Fix #1**: Replace spread operator in `uint8ToBase64()` with chunked processing
2. **Fix #2**: Move size validation to after decoding
3. **Fix #3**: Add bounds checking to Cloudflare label parsing
4. **Fix #4**: Add bounds checking to Cloudflare parameter parsing

### Short-term Actions (Medium)
5. **Fix #5**: Add parameter validation to `readVarBytes()`
6. **Fix #6-7**: Add warnings/errors for truncated cipher suites and extensions
7. **Fix #8**: Update regex to include URL-safe base64 characters
8. **Fix #9**: Improve file type detection heuristic

### Long-term Improvements (Low)
9. Update `ECH_MIN_SIZE` to 11 bytes
10. Add CSP headers
11. Consider adding unit tests for edge cases
12. Add fuzzing tests for parser

---

## Testing Recommendations

### Test Cases to Add

1. **Large input handling**
   - 8KB ECH config (at limit)
   - Multiple large configs

2. **Malformed DNS responses**
   - Labels that exceed data length
   - Parameters that exceed data length
   - Truncated responses

3. **Edge case inputs**
   - Exactly 10-byte configs
   - Configs with odd-length cipher suites
   - Configs with partial extensions
   - URL-safe base64 in DNS records

4. **File upload edge cases**
   - Binary files starting with printable ASCII
   - UTF-8 files with BOM
   - Empty files
   - Maximum size files

---

## Conclusion

The ECHConfig Decoder is a well-designed application with strong defensive programming practices. The identified issues are primarily edge cases and validation improvements rather than fundamental security flaws. The critical issue (#1) is unlikely to manifest with current size limits but should be fixed for future-proofing. The high-severity issues (#2-4) relate to validation and bounds checking that should be addressed to prevent potential exploits or crashes on malformed data.

**Overall Risk Level**: Medium
**Code Quality**: Good
**Security Posture**: Good with room for improvement

