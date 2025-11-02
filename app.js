const ECH_MIN_SIZE = 10;
const ECH_MAX_SIZE = 8192;

// Format detection constants
const ASCII_PRINTABLE_START = 0x20;
const ASCII_PRINTABLE_END = 0x7E;
const MIN_HEX_LENGTH = 4;

const KEM_NAMES = {
    0x0010: 'DHKEM(P-256, HKDF-SHA256)',
    0x0011: 'DHKEM(P-384, HKDF-SHA384)',
    0x0012: 'DHKEM(P-521, HKDF-SHA512)',
    0x0020: 'DHKEM(X25519, HKDF-SHA256)',
    0x0021: 'DHKEM(X448, HKDF-SHA512)'
};

const KDF_NAMES = {
    0x0001: 'HKDF-SHA256',
    0x0002: 'HKDF-SHA384',
    0x0003: 'HKDF-SHA512'
};

const AEAD_NAMES = {
    0x0001: 'AES-128-GCM',
    0x0002: 'AES-256-GCM',
    0x0003: 'ChaCha20Poly1305'
};

const toHexBytes = (uint8Array, separator = ' ') => {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(separator);
};

const uint8ToBase64 = (uint8Array) => {
    return btoa(String.fromCharCode(...uint8Array));
};

const base64ToUint8 = (base64String) => {
    const cleaned = base64String.replace(/\s+/g, '');
    try {
        const binaryString = atob(cleaned);
        return Uint8Array.from(binaryString, char => char.charCodeAt(0));
    } catch (error) {
        throw new Error(`Invalid Base64 string: ${error.message}`);
    }
};

const hexToUint8 = (hexString) => {
    const cleaned = hexString.replace(/[^0-9a-fA-F]/g, '');
    if (cleaned.length === 0) throw new Error('Empty hex string');
    if (cleaned.length % 2 !== 0) throw new Error('Odd-length hex string');
    const bytes = cleaned.match(/.{1,2}/g);
    return new Uint8Array(bytes.map(byte => parseInt(byte, 16)));
};

const validateECHData = (uint8Array) => {
    if (uint8Array.length < ECH_MIN_SIZE) {
        throw new Error(`Data too short (${uint8Array.length} bytes). Minimum ECH config size is ${ECH_MIN_SIZE} bytes.`);
    }
    if (uint8Array.length > ECH_MAX_SIZE) {
        throw new Error(`Data too large (${uint8Array.length} bytes). Maximum reasonable ECH config size is ${ECH_MAX_SIZE} bytes. This doesn't appear to be a valid ECH configuration.`);
    }

    const firstUint16 = (uint8Array[0] << 8) | uint8Array[1];

    if (firstUint16 > 0 && firstUint16 <= (uint8Array.length - 2)) {
        return true;
    }
    if (firstUint16 >= 0xfe00 && firstUint16 <= 0xffff) {
        return true;
    }
    throw new Error('Data does not appear to be a valid ECH configuration (invalid structure).');
};

const validateDomainName = (domain) => {
    const cleanDomain = domain.trim().toLowerCase();
    if (cleanDomain.length === 0) throw new Error('Domain name cannot be empty');
    if (cleanDomain.length > 253) throw new Error('Domain name too long (max 253 characters)');

    if (!/^[a-z0-9._-]+$/.test(cleanDomain)) throw new Error('Domain name contains invalid characters');

    if (cleanDomain.startsWith('.') || cleanDomain.endsWith('.') ||
        cleanDomain.includes('..')) {
        throw new Error('Invalid domain name format');
    }

    if (!cleanDomain.includes('.')) {
        throw new Error('Invalid domain name format (must contain at least one dot)');
    }

    const labels = cleanDomain.split('.');
    for (const label of labels) {
        if (label.length === 0) throw new Error('Invalid domain name format');
        if (label.length > 63) throw new Error('Domain label too long (max 63 characters)');
        if (label.endsWith('-')) {
            throw new Error('Domain labels cannot end with hyphen');
        }
        if (!label.startsWith('_') && label.startsWith('-')) {
            throw new Error('Domain labels cannot start with hyphen (unless service prefix)');
        }
    }

    return cleanDomain;
};

class BinaryReader {
    constructor(uint8Array) {
        this.data = uint8Array;
        this.position = 0;
    }

    remaining() {
        return this.data.length - this.position;
    }

    hasBytes(count) {
        return this.remaining() >= count;
    }

    readUint8() {
        if (!this.hasBytes(1)) {
            throw new Error(`Cannot read uint8: only ${this.remaining()} bytes remaining`);
        }
        return this.data[this.position++];
    }

    readUint16() {
        if (!this.hasBytes(2)) {
            throw new Error(`Cannot read uint16: only ${this.remaining()} bytes remaining`);
        }
        const value = (this.data[this.position] << 8) | this.data[this.position + 1];
        this.position += 2;
        return value;
    }

    readBytes(length) {
        if (!this.hasBytes(length)) {
            throw new Error(`Cannot read ${length} bytes: only ${this.remaining()} bytes remaining`);
        }
        const slice = this.data.slice(this.position, this.position + length);
        this.position += length;
        return slice;
    }

    readVarBytes(lengthBytes = 2) {
        const length = lengthBytes === 1 ? this.readUint8() : this.readUint16();
        return this.readBytes(length);
    }
}

function parseECHConfigList(uint8Array) {
    if (uint8Array.length < 4) {
        throw new Error('Input too short to be valid ECHConfig or ECHConfigList');
    }

    const reader = new BinaryReader(uint8Array);
    const totalLen = reader.readUint16();
    const isLikelyList = totalLen > 0 && totalLen <= (uint8Array.length - 2);

    if (!isLikelyList) {
        return {
            totalLen: uint8Array.length,
            configs: [parseECHConfig(uint8Array)]
        };
    }

    const endPosition = reader.position + totalLen;
    const configs = [];

    try {
        while (reader.position < endPosition) {
            if (!reader.hasBytes(4)) throw new Error('Incomplete config in list');

            const version = reader.readUint16();
            const length = reader.readUint16();

            if (!reader.hasBytes(length)) {
                throw new Error(`Config declares length ${length} but only ${reader.remaining()} bytes remain`);
            }

            const configBytes = reader.readBytes(length);
            const config = { version, length };

            if (version === 0xfe0d) {
                try {
                    config.contents = parseECHConfigContents(configBytes);
                } catch (error) {
                    config.parseError = error.message;
                }
            }

            configs.push(config);
        }
    } catch (error) {
        throw new Error(`Failed to parse config list: ${error.message}`);
    }

    return { totalLen, configs };
}

function parseECHConfig(uint8Array) {
    const reader = new BinaryReader(uint8Array);
    const version = reader.readUint16();
    const length = reader.readUint16();
    const contents = reader.readBytes(length);
    const config = { version, length };

    if (version === 0xfe0d) {
        try {
            config.contents = parseECHConfigContents(contents);
        } catch (error) {
            config.parseError = error.message;
        }
    }

    return config;
}

function parseECHConfigContents(uint8Array) {
    const reader = new BinaryReader(uint8Array);
    const contents = {};

    contents.key_config = {};
    contents.key_config.config_id = reader.readUint8();
    contents.key_config.kem_id = reader.readUint16();

    const publicKey = reader.readVarBytes(2);
    contents.key_config.public_key = {
        len: publicKey.length,
        hex: toHexBytes(publicKey, ''),
        b64: uint8ToBase64(publicKey)
    };

    const suitesBytes = reader.readVarBytes(2);
    const suitesReader = new BinaryReader(suitesBytes);
    contents.key_config.cipher_suites = [];

    while (suitesReader.hasBytes(4)) {
        contents.key_config.cipher_suites.push({
            kdf: suitesReader.readUint16(),
            aead: suitesReader.readUint16()
        });
    }

    contents.maximum_name_length = reader.readUint8();

    const publicNameBytes = reader.readVarBytes(1);
    try {
        contents.public_name = new TextDecoder('utf-8', { fatal: true }).decode(publicNameBytes);
    } catch {
        contents.public_name = `<non-UTF8: ${toHexBytes(publicNameBytes, '')}>`;
    }

    const extensionsBytes = reader.readVarBytes(2);
    const extensionsReader = new BinaryReader(extensionsBytes);
    contents.extensions = [];

    while (extensionsReader.hasBytes(4)) {
        const type = extensionsReader.readUint16();
        const data = extensionsReader.readVarBytes(2);
        contents.extensions.push({
            type,
            len: data.length,
            hex: toHexBytes(data, '')
        });
    }

    return contents;
}

function detectAndDecode(inputString) {
    const cleaned = inputString.trim();

    if (!cleaned) {
        return { data: new Uint8Array(), format: 'empty' };
    }

    if (cleaned.length > ECH_MAX_SIZE) {
        throw new Error(`Input too large (${(cleaned.length / 1024).toFixed(1)}KB, max ${ECH_MAX_SIZE / 1024}KB)`);
    }

    // Check for multiple ECH configs separated by blank lines (two or more newlines)
    if (/\n\s*\n/.test(cleaned)) {
        const parts = cleaned.split(/\n\s*\n/).filter(part => part.trim().length > 0);

        if (parts.length > 1) {
            // Try to parse each part as an ECH config
            const configs = [];
            let allValid = true;

            for (const part of parts) {
                try {
                    const result = detectAndDecodeSingle(part.trim());
                    if (result.format !== 'empty') {
                        configs.push(result);
                    }
                } catch {
                    allValid = false;
                    break;
                }
            }

            if (allValid && configs.length > 1) {
                return {
                    multiple: true,
                    configs: configs,
                    format: `Multiple ECH configs (${configs.length})`
                };
            }
        }
    }

    // Single config
    return detectAndDecodeSingle(cleaned);
}

function detectAndDecodeSingle(cleaned) {
    const echMatch = cleaned.match(/\bech=["']?([A-Za-z0-9+/=]+)["']?/i);
    if (echMatch) {
        return { data: base64ToUint8(echMatch[1]), format: 'DNS HTTPS Record (ech= parameter)' };
    }

    const pemMatch = cleaned.match(/-+BEGIN ECHCONFIG-+\s*([\s\S]+?)\s*-+END ECHCONFIG-+/i);
    if (pemMatch) {
        const pemBody = pemMatch[1].replace(/[^A-Za-z0-9+/=]/g, '');
        return { data: base64ToUint8(pemBody), format: 'PEM (ECHCONFIG)' };
    }

    if (/^[0-9a-fA-F\s]+$/.test(cleaned)) {
        const hexOnly = cleaned.replace(/\s+/g, '');
        if (hexOnly.length >= MIN_HEX_LENGTH) {
            return { data: hexToUint8(cleaned), format: 'Hex' };
        }
    }

    try {
        const decoded = base64ToUint8(cleaned);
        if (decoded.length > 0) {
            return { data: decoded, format: 'Base64' };
        }
    } catch (error) {
        //continue
    }

    throw new Error('Unknown input format. Please provide Base64, hex, ECH PEM, DNS HTTPS record (ech=...), or upload a binary file.');
}

function renderParsedConfig(parsed) {
    const container = document.createElement('div');

    const summary = document.createElement('div');
    summary.className = 'small';
    const summaryText = document.createTextNode(`Total length: `);
    const summaryBold1 = document.createElement('b');
    summaryBold1.textContent = parsed.totalLen;
    const summaryText2 = document.createTextNode(` bytes | Configs: `);
    const summaryBold2 = document.createElement('b');
    summaryBold2.textContent = parsed.configs.length;
    summary.appendChild(summaryText);
    summary.appendChild(summaryBold1);
    summary.appendChild(summaryText2);
    summary.appendChild(summaryBold2);
    container.appendChild(summary);

    parsed.configs.forEach((config, index) => {
        const section = document.createElement('div');
        section.style.marginTop = '16px';

        const heading = document.createElement('h3');
        heading.textContent = `Config #${index + 1}`;
        section.appendChild(heading);

        const table = document.createElement('table');

        addTableRow(table, 'Version', `0x${config.version.toString(16).padStart(4, '0')} (${config.version})`);
        addTableRow(table, 'Length', `${config.length} bytes`);

        if (config.parseError) {
            const errorSpan = document.createElement('span');
            errorSpan.className = 'error';
            errorSpan.textContent = config.parseError;
            addTableRow(table, 'Parse Error', errorSpan);
        }

        if (config.contents) {
            const c = config.contents;
            const k = c.key_config;

            addTableRow(table, 'Config ID', k.config_id.toString());
            addTableRow(table, 'KEM ID', `${k.kem_id} (${getKemName(k.kem_id)})`);
            addTableRow(table, 'Public Key (hex)', k.public_key.hex);
            addTableRow(table, 'Public Key (base64)', k.public_key.b64);

            if (k.cipher_suites.length > 0) {
                const suitesContainer = document.createElement('div');
                k.cipher_suites.forEach((s, idx) => {
                    if (idx > 0) suitesContainer.appendChild(document.createElement('br'));
                    const suiteText = document.createTextNode(`KDF: ${s.kdf} (${getKdfName(s.kdf)}), AEAD: ${s.aead} (${getAeadName(s.aead)})`);
                    suitesContainer.appendChild(suiteText);
                });
                addTableRow(table, 'Cipher Suites', suitesContainer);
            } else {
                const noneItalic = document.createElement('i');
                noneItalic.textContent = 'none';
                addTableRow(table, 'Cipher Suites', noneItalic);
            }

            addTableRow(table, 'Maximum Name Length', c.maximum_name_length.toString());
            addTableRow(table, 'Public Name', c.public_name);

            if (c.extensions.length > 0) {
                const extsContainer = document.createElement('div');
                c.extensions.forEach((e, idx) => {
                    if (idx > 0) extsContainer.appendChild(document.createElement('hr'));

                    const extDiv = document.createElement('div');
                    const typeBold = document.createElement('b');
                    typeBold.textContent = 'Type:';
                    const typeText = document.createTextNode(` ${e.type}, `);
                    const lenBold = document.createElement('b');
                    lenBold.textContent = 'Length:';
                    const lenText = document.createTextNode(` ${e.len}`);

                    extDiv.appendChild(typeBold);
                    extDiv.appendChild(typeText);
                    extDiv.appendChild(lenBold);
                    extDiv.appendChild(lenText);
                    extDiv.appendChild(document.createElement('br'));

                    const codeElem = document.createElement('code');
                    codeElem.textContent = e.hex;
                    extDiv.appendChild(codeElem);

                    extsContainer.appendChild(extDiv);
                });
                addTableRow(table, 'Extensions', extsContainer);
            } else {
                const noneItalic = document.createElement('i');
                noneItalic.textContent = 'none';
                addTableRow(table, 'Extensions', noneItalic);
            }
        }

        section.appendChild(table);
        container.appendChild(section);
    });

    return container;
}

function addTableRow(table, headerText, content) {
    const row = document.createElement('tr');

    const th = document.createElement('th');
    th.textContent = headerText;
    row.appendChild(th);

    const td = document.createElement('td');
    if (typeof content === 'string') {
        td.textContent = content;
    } else {
        td.appendChild(content);
    }
    row.appendChild(td);

    table.appendChild(row);
}

function getKemName(kemId) {
    return KEM_NAMES[kemId] || 'Unknown';
}

function getKdfName(kdfId) {
    return KDF_NAMES[kdfId] || 'Unknown';
}

function getAeadName(aeadId) {
    return AEAD_NAMES[aeadId] || 'Unknown';
}

function processFileBytes(rawBytes, fileName, source) {
    const isProbablyText = rawBytes.length > 0 && rawBytes[0] >= ASCII_PRINTABLE_START && rawBytes[0] <= ASCII_PRINTABLE_END;

    if (isProbablyText) {
        try {
            const text = new TextDecoder('utf-8').decode(rawBytes);
            const decoded = detectAndDecode(text);
            return {
                data: decoded.data,
                format: `${decoded.format} from ${source} (${fileName})`,
                inputText: text
            };
        } catch (textError) {
            return {
                data: rawBytes,
                format: `Binary file from ${source} (${fileName})`,
                inputText: null
            };
        }
    } else {
        return {
            data: rawBytes,
            format: `Binary file from ${source} (${fileName})`,
            inputText: null
        };
    }
}

function initializeApp() {
    const elements = {
        input: document.getElementById('inputArea'),
        output: document.getElementById('output'),
        rawHex: document.getElementById('rawHex'),
        manualStatus: document.getElementById('manualStatus'),
        dnsStatus: document.getElementById('dnsStatus'),
        inputType: document.getElementById('inputType'),
        decodeBtn: document.getElementById('decodeBtn'),
        clearBtn: document.getElementById('clearBtn'),
        fetchBtn: document.getElementById('fetchBtn'),
        fileInput: document.getElementById('fileInput'),
        domainInput: document.getElementById('domainInput')
    };

    const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform);
    const pasteKey = isMac ? 'Cmd+V' : 'Ctrl+V';
    elements.input.placeholder = `Paste Base64, hex, ECH PEM, DNS HTTPS record, or ${pasteKey} a file`;

    elements.input.value = '';
    elements.domainInput.value = '';
    elements.rawHex.textContent = '';
    elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
    elements.inputType.textContent = '';
    clearAllStatus(elements);

    elements.decodeBtn.addEventListener('click', () => {
        try {
            clearAllStatus(elements);
            elements.domainInput.value = '';

            const result = detectAndDecode(elements.input.value);

            // Handle multiple configs
            if (result.multiple) {
                elements.inputType.textContent = `Input detected: ${result.format}`;
                elements.rawHex.textContent = '';
                elements.output.textContent = '';

                const container = document.createElement('div');

                result.configs.forEach((config, index) => {
                    validateECHData(config.data);
                    const parsed = parseECHConfigList(config.data);

                    const recordSection = document.createElement('div');
                    recordSection.style.marginTop = index > 0 ? '24px' : '0';
                    recordSection.style.paddingTop = index > 0 ? '24px' : '0';
                    if (index > 0) {
                        recordSection.style.borderTop = '2px solid #e2e8f0';
                    }

                    const recordHeader = document.createElement('h2');
                    recordHeader.textContent = `ECH Config #${index + 1}`;
                    recordHeader.style.fontSize = '18px';
                    recordHeader.style.marginBottom = '12px';
                    recordHeader.style.color = '#0b1220';
                    recordSection.appendChild(recordHeader);

                    const formatInfo = document.createElement('div');
                    formatInfo.className = 'input-type-label';
                    formatInfo.textContent = `Format: ${config.format}`;
                    formatInfo.style.marginBottom = '8px';
                    recordSection.appendChild(formatInfo);

                    const hexTitle = document.createElement('div');
                    hexTitle.className = 'section-title';
                    hexTitle.textContent = 'Raw bytes (hex)';
                    hexTitle.style.marginTop = '12px';
                    recordSection.appendChild(hexTitle);

                    const hexDisplay = document.createElement('div');
                    hexDisplay.className = 'raw-hex-display';
                    hexDisplay.textContent = toHexBytes(config.data, ' ');
                    recordSection.appendChild(hexDisplay);

                    const parsedTitle = document.createElement('div');
                    parsedTitle.className = 'section-title';
                    parsedTitle.textContent = 'Parsed output';
                    parsedTitle.style.marginTop = '12px';
                    recordSection.appendChild(parsedTitle);

                    recordSection.appendChild(renderParsedConfig(parsed));

                    container.appendChild(recordSection);
                });

                elements.output.appendChild(container);
                return;
            }

            // Handle single config
            const { data, format } = result;

            if (data.length === 0) {
                showManualError(elements, 'No input provided');
                return;
            }

            validateECHData(data);
            const parsed = parseECHConfigList(data);
            displayResults(elements, data, format, parsed);

        } catch (error) {
            elements.rawHex.textContent = '';
            elements.inputType.textContent = '';
            elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
            showManualError(elements, error.message);
        }
    });

    elements.clearBtn.addEventListener('click', () => {
        elements.input.value = '';
        elements.domainInput.value = '';
        elements.rawHex.textContent = '';
        elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
        elements.inputType.textContent = '';
        clearAllStatus(elements);
    });

    elements.fileInput.addEventListener('change', async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        if (file.size > ECH_MAX_SIZE) {
            showManualError(elements, `File too large: ${(file.size / 1024).toFixed(1)}KB (max ${ECH_MAX_SIZE / 1024}KB)`);
            event.target.value = '';
            return;
        }

        try {
            clearAllStatus(elements);
            elements.domainInput.value = '';

            const arrayBuffer = await file.arrayBuffer();
            const rawBytes = new Uint8Array(arrayBuffer);

            const result = processFileBytes(rawBytes, file.name, 'file');

            validateECHData(result.data);
            const parsed = parseECHConfigList(result.data);

            const inputText = result.inputText !== null ? result.inputText : uint8ToBase64(result.data);
            elements.input.value = inputText;
            displayResults(elements, result.data, result.format, parsed);

        } catch (error) {
            elements.rawHex.textContent = '';
            elements.inputType.textContent = '';
            elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
            showManualError(elements, `File error: ${error.message}`);
        }

        event.target.value = '';
    });

    elements.fetchBtn.addEventListener('click', async () => {
        let input = elements.domainInput.value.trim();

        if (!input) {
            showDnsError(elements, 'Please enter a domain name or URL');
            return;
        }

        let domain = input;
        if (input.match(/^https?:\/\//i)) {
            try {
                const url = new URL(input);
                domain = url.hostname;
            } catch (e) {
                showDnsError(elements, 'Invalid URL format');
                return;
            }
        } else if (input.includes('/')) {
            domain = input.split('/')[0];
        }

        let validatedDomain;
        try {
            validatedDomain = validateDomainName(domain);
        } catch (error) {
            showDnsError(elements, error.message);
            return;
        }

        const provider = document.querySelector('input[name="dnsProvider"]:checked').value;

        try {
            elements.fetchBtn.disabled = true;
            clearAllStatus(elements);
            elements.input.value = '';
            showDnsStatus(elements, 'Fetching ECH from DNS...', false);

            const echDataArray = await fetchECHFromDNS(validatedDomain, provider);

            if (echDataArray.length === 1) {
                const echData = echDataArray[0];
                validateECHData(echData.data);
                const parsed = parseECHConfigList(echData.data);

                elements.input.value = echData.base64;
                displayResults(elements, echData.data, `DNS HTTPS RR from ${validatedDomain}`, parsed);
                showDnsStatus(elements, `✓ Successfully fetched ECH from ${validatedDomain}`, true);
            } else {
                elements.inputType.textContent = `Input detected: DNS HTTPS RR from ${validatedDomain} (${echDataArray.length} records with ECH)`;
                elements.rawHex.textContent = '';
                elements.output.textContent = '';

                const container = document.createElement('div');

                echDataArray.forEach((echData, index) => {
                    validateECHData(echData.data);
                    const parsed = parseECHConfigList(echData.data);

                    const recordSection = document.createElement('div');
                    recordSection.style.marginTop = index > 0 ? '24px' : '0';
                    recordSection.style.paddingTop = index > 0 ? '24px' : '0';
                    if (index > 0) {
                        recordSection.style.borderTop = '2px solid #e2e8f0';
                    }

                    const recordHeader = document.createElement('h2');
                    recordHeader.textContent = `HTTPS Record #${echData.recordIndex}`;
                    recordHeader.style.fontSize = '18px';
                    recordHeader.style.marginBottom = '12px';
                    recordHeader.style.color = '#0b1220';
                    recordSection.appendChild(recordHeader);

                    const hexTitle = document.createElement('div');
                    hexTitle.className = 'section-title';
                    hexTitle.textContent = 'Raw bytes (hex)';
                    hexTitle.style.marginTop = '12px';
                    recordSection.appendChild(hexTitle);

                    const hexDisplay = document.createElement('div');
                    hexDisplay.className = 'raw-hex-display';
                    hexDisplay.textContent = toHexBytes(echData.data, ' ');
                    recordSection.appendChild(hexDisplay);

                    const parsedTitle = document.createElement('div');
                    parsedTitle.className = 'section-title';
                    parsedTitle.textContent = 'Parsed output';
                    parsedTitle.style.marginTop = '12px';
                    recordSection.appendChild(parsedTitle);

                    recordSection.appendChild(renderParsedConfig(parsed));

                    container.appendChild(recordSection);
                });

                elements.output.appendChild(container);

                const allBase64 = echDataArray.map(e => e.base64).join('\n\n');
                elements.input.value = allBase64;

                showDnsStatus(elements, `✓ Successfully fetched ${echDataArray.length} ECH configs from ${validatedDomain}`, true);
            }

        } catch (error) {
            elements.rawHex.textContent = '';
            elements.inputType.textContent = '';
            elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
            showDnsError(elements, `${validatedDomain}: ${error.message}`);
        } finally {
            elements.fetchBtn.disabled = false;
        }
    });

    elements.domainInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            elements.fetchBtn.click();
        }
    });

    elements.input.addEventListener('paste', async (event) => {
        const items = event.clipboardData?.items;
        if (!items) return;

        for (const item of items) {
            if (item.kind === 'file') {
                event.preventDefault();
                const file = item.getAsFile();
                if (!file) continue;

                if (file.size > ECH_MAX_SIZE) {
                    showManualError(elements, `File too large: ${(file.size / 1024).toFixed(1)}KB (max ${ECH_MAX_SIZE / 1024}KB)`);
                    break;
                }

                try {
                    clearAllStatus(elements);
                    elements.domainInput.value = '';

                    const arrayBuffer = await file.arrayBuffer();
                    const rawBytes = new Uint8Array(arrayBuffer);

                    const result = processFileBytes(rawBytes, file.name, 'pasted file');

                    validateECHData(result.data);
                    const parsed = parseECHConfigList(result.data);

                    const inputText = result.inputText !== null ? result.inputText : uint8ToBase64(result.data);
                    elements.input.value = inputText;
                    displayResults(elements, result.data, result.format, parsed);

                } catch (error) {
                    elements.rawHex.textContent = '';
                    elements.inputType.textContent = '';
                    elements.output.textContent = 'Press Decode, upload a file, or fetch from DNS to see results.';
                    showManualError(elements, `Paste error: ${error.message}`);
                }

                break;
            }
        }
    });
}

function displayResults(elements, data, format, parsed) {
    elements.inputType.textContent = `Input detected: ${format}`;
    elements.rawHex.textContent = toHexBytes(data, ' ');
    elements.output.textContent = '';
    elements.output.appendChild(renderParsedConfig(parsed));
}

function showManualError(elements, message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.setAttribute('role', 'alert');
    errorDiv.textContent = `Error: ${message}`;
    elements.manualStatus.textContent = '';
    elements.manualStatus.appendChild(errorDiv);
}

function showDnsError(elements, message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.setAttribute('role', 'alert');
    errorDiv.textContent = `Error: ${message}`;
    elements.dnsStatus.textContent = '';
    elements.dnsStatus.appendChild(errorDiv);
}

function showDnsStatus(elements, message, isSuccess) {
    const statusDiv = document.createElement('div');
    statusDiv.className = isSuccess ? 'success' : '';
    statusDiv.setAttribute('role', 'status');
    statusDiv.setAttribute('aria-live', 'polite');
    statusDiv.textContent = message;
    elements.dnsStatus.textContent = '';
    elements.dnsStatus.appendChild(statusDiv);
}

function clearAllStatus(elements) {
    elements.manualStatus.textContent = '';
    elements.dnsStatus.textContent = '';
}

async function fetchECHFromDNS(domain, provider = 'google') {
    let url, headers = {};

    if (provider === 'cloudflare') {
        url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=HTTPS`;
        headers = { 'Accept': 'application/dns-json' };
    } else {
        url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=HTTPS`;
    }

    const response = await fetch(url, { headers });

    if (!response.ok) {
        throw new Error(`DNS query failed: ${response.status} ${response.statusText}`);
    }

    const json = await response.json();

    if (json.Status !== 0) {
        throw new Error(`DNS query returned status ${json.Status}`);
    }

    const answers = json.Answer || [];

    if (answers.length === 0) {
        throw new Error('No HTTPS resource records found for this domain');
    }

    let echConfigs;

    if (provider === 'cloudflare') {
        echConfigs = parseCloudflareECH(answers);
    } else {
        echConfigs = parseGoogleECH(answers);
    }

    if (!echConfigs || echConfigs.length === 0) {
        throw new Error('No ECH configuration found in HTTPS record (no ech= parameter)');
    }

    return echConfigs.map((config, index) => ({
        base64: config.base64,
        data: base64ToUint8(config.base64),
        recordIndex: index + 1,
        record: config.record
    }));
}

function parseGoogleECH(answers) {
    const echConfigs = [];

    for (const answer of answers) {
        const data = answer.data || '';
        const echMatch = data.match(/\bech=([A-Za-z0-9+/=]+)/i);

        if (echMatch) {
            echConfigs.push({
                base64: echMatch[1],
                record: data
            });
        }
    }

    return echConfigs;
}

function parseCloudflareECH(answers) {
    const echConfigs = [];

    for (const answer of answers) {
        const data = answer.data || '';
        const wireMatch = data.match(/\\#\s+\d+\s+([0-9a-f\s]+)/i);

        if (!wireMatch) continue;

        const hexString = wireMatch[1].replace(/\s+/g, '');
        const bytes = hexToUint8(hexString);

        let i = 2;

        while (i < bytes.length && bytes[i] !== 0) {
            const labelLen = bytes[i];
            if (labelLen === 0) break;
            i += 1 + labelLen;
        }
        i++;

        while (i < bytes.length - 3) {
            const key = (bytes[i] << 8) | bytes[i + 1];
            const len = (bytes[i + 2] << 8) | bytes[i + 3];

            if (key === 5 && i + 4 + len <= bytes.length) {
                const echBytes = bytes.slice(i + 4, i + 4 + len);
                echConfigs.push({
                    base64: uint8ToBase64(echBytes),
                    record: data
                });
                break;
            }

            i += 4 + len;
        }
    }

    return echConfigs;
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}