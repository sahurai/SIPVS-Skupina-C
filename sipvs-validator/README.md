# sipvs-validator

This application verifies ASiC-E containers with a XAdES-T
signature.

The validator stops at the first fault. The message names the element or attribute,
the found value and the expected value. The web page shows the XML and highlights only the wrong
value.

## Run

Requirements: JDK 17 or newer, and internet access. ArchiveTimeStamp check
download the CRL of the DITEC test CA (`XadesConstants.CRL_URL`). The CRL must be signed by
that CA, and its `nextUpdate` time must not be in the past. The DITEC CRL is valid for 24
hours (`nextUpdate` is one day after `thisUpdate`). If no newer CRL is published in time, every
file that reaches step 3a fails there with "CRL platí do ...".

The validator keeps a CRL that passed these checks and uses it for all files until its
`nextUpdate`. Then it downloads the CRL again. A CRL that fails a check is not kept, so the next
file downloads it again.

```bash
cd sipvs-validator
./mvnw spring-boot:run
```

Open http://localhost:8081. Upload one or more `.asice` files and press "Overiť" or "Overiť
všetky". For a failed file, "Zobraziť XML" shows the file with the fault and marks the wrong
attribute value, element text or tag name.

The log lists the content of every uploaded container before any check runs, so it shows the
content of a failed file too. There is one line per file, with its name, unpacked size and
compression method. A last line gives the number of files and the total size:

```
protokol-t.asice: mimetype (31 B, STORED)
protokol-t.asice: META-INF/signatures.xml (11546 B, DEFLATED)
protokol-t.asice: 5 file(s), 98213 B unpacked
```

The log shows control characters and line separators in text from the upload as `?`. This
covers file names, entry names, XML values and error messages. An unexpected error, in one file
or in a request, is logged with its full stack trace, and its exception message is logged as it
is.

## API

`POST /api/validate` with one or more multipart parts named `file`.

The response has one result per file:

```json
{"files": [{"name": "protokol-t.asice",
  "error": "ds:DigestValue: nie je správny. ...",
  "location": {"file": "META-INF/signatures.xml", "path": "/*[1]/*[1]/*[1]/*[4]/*[3]",
               "mark": "TEXT", "content": "<?xml ..."}}]}
```

- A valid file has `size` and no `error`.
- `location.path` is an XPath to the element with the fault.
- `location.mark` is `ATTRIBUTE` (then `location.attribute` names it), `TEXT` or `TAG`.
- Without a file the answer is HTTP 400. A file over 20 MB gives HTTP 413.

## Validation steps

The steps run in this order. The first failed check stops the validation.

| Step | What is checked |
|---|---|
| container | ZIP without a ZIP64 end record, central directory equal to the local headers (same files in the same order, same compression method and content), `mimetype` (exact content, first entry, not compressed), size limits (20 MB unpacked, 1 MB for each signature file and the manifest), duplicate entries, `META-INF/signatures<digits>.xml`, well-formed XML |
| 1a, 1b | `xzep:SignatureVersion`, `xmlns:ds`, `xmlns:asic`, root `asic:XAdESSignatures` |
| 1c | UTF-8, prefixes `ds`, `xades`, `xadesv141`, `xzep`, `asic`, `dsm`, required `xmlns:` declarations, unique Ids |
| 2a, 2b | SignatureMethod, CanonicalizationMethod, Transforms and DigestMethod from profile 4.5; RSA-PSS parameters |
| 2c | Signature structure, Ids, references and their `Type`, KeyInfo and the certificate, SignatureProperties, ProductInfos, base64 values, exactly two `ds:Object`, the `ds:SignatureProperty` content against the xzep schema of profile 4.2.8 |
| 2d | QualifyingProperties, signed and unsigned properties, DataObjectFormat, SigningTime, SigningCertificate, policy, time-stamps (one `xades:EncapsulatedTimeStamp`, no `xades:Include` or `xades:XMLTimeStamp`), CertificateValues path, RevocationValues (a CRL or OCSP response for the signing certificate), OCSP, schema validation of the signature file |
| 2e | Data objects (XML container, PDF with `pdfaid:part` 1 in the XMP metadata of the catalog, PNG, TXT), manifest (each file once, UTF-8), Ids in data objects, embedded XSD and XSLT of the XML container |
| 3a | Signing certificate valid at the time-stamp time, not revoked and issued by the trusted CA; CRL signed by that CA and not expired |
| 4a, 4b | SignatureTimeStamp and ArchiveTimeStamp: TSA certificate (valid, not revoked, a critical extended key usage that is only id-kp-timeStamping as RFC 3161 2.3 requires, issued by the trusted CA), CRL, token signature (also the ESS signing certificate of the token and the certificate validity at the time-stamp time), message imprint and its hash function (profile 4.5) |
| 5a, 5b | Reference digests and the signature value (RSA-PSS key parameters too) |

Two choices are stricter than the profile:
- Only XAdES-T or higher is accepted. A XAdES-B file fails at 2d (no `xades:UnsignedProperties`).
- A `Type` attribute on a reference to a file is rejected.

## Untrusted input

The validator parses uploaded XML and runs the XSD and XSLT embedded in the XML container.
All parsers forbid external DTDs, schemas and stylesheets. Schema imports resolve only to the
bundled schemas in `src/main/resources/schemas/` (W3C XML Signature, ETSI XAdES 1.3.2 and 1.4.1,
ETSI ASiC, RFC 6931, and the xzep schema copied from profile 4.2.8). The XSLT runs with secure processing, without `xsl:import`,
`xsl:include` or `document()` to other files, and with an output limit.

The validator reads a container through its local headers. `unzip` and most other tools read
the central directory at the end of the ZIP. So both must list the same files in the same
order, with the same compression method and the same content. Otherwise another tool could
unpack files that were never validated.

Limits against files that use too much memory or time:
- The unpacked files of one container have at most 20 MB together. This is also the upload
  limit. The limits count the bytes really unpacked, not the sizes in the ZIP headers.
- Each XML file has at most 1 MB. A signature file or the manifest fails while it is unpacked.
  An XML data object fails before it is parsed. A DOM can take about 45 times the size of its
  XML on the heap. The XML files of the course samples have at most 16 KB.
- A ZIP64 end record fails the container. A container under 20 MB never needs one. Its entry
  count has no limit, and the JDK `ZipFile` sizes its tables by it.
- Every XML parser stops at nesting depth 1000 (`jdk.xml.maxElementDepth`). Deeper XML fails
  as not well-formed.
- Each XSLT transformation has 5 seconds. It runs on a pool of at most 4 threads. After 5
  seconds the file fails, but the thread cannot be stopped: it runs until the stylesheet ends.
  When all 4 threads are busy, a new transformation fails with "overte súbor znova neskôr".
- A PNG is decoded only when its header gives at most 50,000,000 pixels and at most 64 MB of
  decoded pixels. The header gives the size: width x height x samples x bytes per sample. Gray
  and RGB images count one more sample for transparency.
- At most 4 files are validated at the same time. When all 4 run, a new file fails with
  "overte súbor znova neskôr".
- Any other error in one file, also `StackOverflowError` or `OutOfMemoryError`, gives
  "Nastala neočakávaná chyba." for that file, not HTTP 500.

Trust: the signing certificate, each TSA certificate and the CRL must be signed by the
DITEC Test CA SHA256 RSA certificate in `src/main/resources/certificates/`. A copied issuer
name is not enough. `TrustAnchorUtil` gives the download address, the date and the SHA-256
fingerprint of that file.

File names: reference URIs are percent-decoded (RFC 3986) before they are compared with file
names, so `my%20zmluva.pdf` points to `my zmluva.pdf`. A `+` stays a `+`.

## Code

| Path | Content |
|---|---|
| `services/ValidationService.java` | Opens each uploaded file and runs the steps for each signature, in the order of the table above |
| `services/steps/ProfileValidator.java` | Steps 1a to 1c |
| `services/steps/AlgorithmValidator.java` | Steps 2a and 2b |
| `services/steps/SignatureStructureValidator.java` | Step 2c |
| `services/steps/QualifyingPropertiesValidator.java` | Step 2d |
| `services/steps/DataObjectValidator.java` | Step 2e: data objects, manifest and Ids in the data objects |
| `services/steps/XmlDataContainerValidator.java` | Step 2e: the XML container with its embedded XSD and XSLT |
| `services/steps/SigningCertificateValidator.java` | Step 3a |
| `services/steps/TimestampValidator.java` | Steps 4a and 4b |
| `services/steps/CoreValidator.java` | Steps 5a and 5b |
| `services/steps/CertificateTrustValidator.java` | Checks for 3a and 4a: validity time, the downloaded CRL and the trusted CA |
| `services/steps/Container.java` | Data of one container: files, Ids, schema errors, the parsed manifest and the CRL, shared by all its signatures |
| `services/steps/SignatureContext.java` | The `ds:Signature` that is checked now, with lookups of its parts |
| `controllers/ValidateController.java` | `POST /api/validate` |
| `utils/ValidationUtil.java` | Checks used by several steps, `error()`, which links a fault to its XML node, and `safe()`, which cleans upload text for the log |
| `utils/` | ASiC-E reading, XML, certificates, trust anchor, crypto, schemas, algorithms and constants of the profile |
| `converters/` | Base64, hex, canonicalization, certificates, time-stamps, URIs, XML, XSLT |
| `enums/Detail.java`, `messages.properties` | Fault types and their Slovak messages |
| `static/index.html` | Upload page and XML viewer |

## Tests

```bash
./mvnw test
```

The tests use the 13 course samples in `src/test/resources/samples/`. Each sample must fail at
its known first fault. Other tests edit a sample, or sign a container with generated keys, a
generated TSA and a mocked CRL; they trust the generated root instead of the DITEC CA. The
tests for samples 12 and 13 download the live CRL, so they fail when it is expired.
