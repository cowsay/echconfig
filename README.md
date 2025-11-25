# ECHConfig Decoder

A web-based tool for decoding and parsing Encrypted Client Hello (ECH) configurations as specified in the [draft-ietf-tls-esni](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni). This application supports multiple input formats and provides detailed parsing of ECHConfig and ECHConfigList structures.

## Live Demo

[https://cowsay.github.io/echconfig/](https://cowsay.github.io/echconfig/)

## Features

### Input Format Support

- **Base64**: Standard base64-encoded ECH configurations
- **Hexadecimal**: Hex strings with or without whitespace separators
- **DNS HTTPS Records**: Direct extraction from DNS record syntax ([draft-ietf-tls-svcb-ech](https://datatracker.ietf.org/doc/html/draft-ietf-tls-svcb-ech))
- **PEM Format**: ECH configurations wrapped in PEM delimiters ([draft-farrell-tls-pemesni](https://datatracker.ietf.org/doc/html/draft-farrell-tls-pemesni))
- **Binary Files**: Upload `.ech`, `.pem`, `.bin`, or other binary formats
- **Multiple Configurations**: Automatic detection and parsing of multiple ECH configs separated by blank lines

### DNS API Integration

Query live domains for ECH configurations via DNS HTTPS resource records:

- **Google DNS API**: Query using Google's public dns-query JSON API (`dns.google`)
- **Cloudflare DNS API**: Query using Cloudflare's public dns-query JSON API (`cloudflare-dns.com`)
- **Wire Format Parsing**: Automatic parsing of both text and wire format responses
- **Service/Port-Prefixed Records**: Support for records like `_3443._https.domain.com` ([rfc9460#name-svcb-query-names](https://datatracker.ietf.org/doc/html/rfc9460#name-svcb-query-names))
- **Multiple Records**: Display and decode all ECH configurations from multiple HTTPS records

### Parsing Capabilities

The decoder provides comprehensive parsing of ECH structures:

- **Version Detection**: Identifies ECH protocol version
- **Key Configuration**: Extracts KEM ID, public key, and cipher suites
- **Cipher Suite Details**: Human-readable names for KDF and AEAD algorithms
- **Extensions**: Parses and displays ECH extensions
- **Public Name**: Decodes the public_name field with UTF-8 validation
- **Validation**: Structural validation to detect malformed configurations

## Usage

### Manual Input

1. Paste an ECH configuration in any supported format into the input textarea
2. Click "Decode" to parse and display the configuration
3. View raw bytes in hexadecimal and parsed structure

### File Upload

1. Click "Upload File" to select a local file
2. Supports text files (Base64, hex, PEM) and binary files
3. Automatic format detection and parsing

### DNS Query

1. Enter a domain name (e.g., `cloudflare-ech.com`)
2. Select DNS provider (Google or Cloudflare)
3. Click "Fetch from DNS" to query and decode

## Privacy

All processing occurs client-side in your browser:
- No data is sent to any server except DNS API queries (optional)
- DNS API queries are sent to the selected provider (Google or Cloudflare)
- No tracking or analytics

## License

MIT License
