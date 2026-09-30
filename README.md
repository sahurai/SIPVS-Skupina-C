# SIPVS – Ubytovací protokol (ŠD Mladosť)

This application is the semester project for SIPVS. It is an electronic version of the check-in
protocol of the Mladosť dormitory. A student completes the protocol on arrival. The dormitory
system assigns the room, thus the form has no room fields.

The project has four parts. Each part adds functions to the same application.

| Part | Function | Status |
|---|---|---|
| 1 | XML form: save XML, validate against XSD, transform to HTML | done |
| 2 | Electronic signature: sign the XML and a PDF with D.Signer, save an ASiC-E container | done |
| 3 | Timestamp: extend XAdES-BES to XAdES-T | not started |
| 4 | Verification of the XAdES-T signature | not started |

## Files

| Path | Content |
|---|---|
| `schema/protokol.xsd` | Structure of the form. Namespace `urn:mladost:ubytovaci-protokol:1.0`. |
| `schema/protokol.xsl` | XSLT 1.0 transformation to XHTML. The output looks like the paper form. |
| `samples/protokol.xml` | A valid instance. |
| `samples/protokol-chybny.xml` | An instance with eight errors. Use it to show the validation report. |
| `src/main/resources/static/index.html` | The web form. Bootstrap 5 comes from the `org.webjars:bootstrap` dependency. The D.Bridge JS library comes from slovensko.sk. |
| `src/main/java/sk/fiit/sipvs/XmlService.java` | Save, validate and transform. JDK classes only. |
| `src/main/java/sk/fiit/sipvs/PodpisService.java` | Prepares the data for the signer. Makes the PDF. Saves the ASiC-E container. |
| `src/main/java/sk/fiit/sipvs/ProtokolController.java` | The REST endpoints that the page calls. |
| `src/main/resources/fonts/` | Liberation Serif. The PDF embeds this font. |
| `src/main/resources/sRGB.icc` | Colour profile for the PDF/A output. |
| `data/` | Output of the application. Not in git. |

## Requirements

- JDK 17 or newer.
- Internet access for the first build. The Maven wrapper downloads Maven and the dependencies.
- For part 2: D.Suite/eIDAS from slovensko.sk, the browser extension D.Bridge 2, and the test
  certificate. See [Set up the signer](#set-up-the-signer).

## Run on Linux or macOS

1. Open a terminal in the project folder.
2. Start the application:

   ```bash
   JAVA_HOME=/usr/lib/jvm/java-17-openjdk ./mvnw spring-boot:run
   ```

   On Arch Linux the default `java` can be an older version. Set `JAVA_HOME` as shown, or make
   JDK 17 the default with `archlinux-java set java-17-openjdk`.

3. Open <http://localhost:8080> in the browser.

## Run on Windows

1. Install a JDK 17 or newer, for example from <https://adoptium.net>. Select the option
   **Set JAVA_HOME variable** in the installer.
2. Open **PowerShell** in the project folder. In File Explorer, hold **Shift**, right-click the
   folder and select **Open PowerShell window here**.
3. Make sure that Java is found:

   ```powershell
   java -version
   ```

   If the command fails, set the variable for this window. Use your JDK path:

   ```powershell
   $env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17"
   ```

4. Start the application:

   ```powershell
   .\mvnw.cmd spring-boot:run
   ```

   The first start downloads Maven and the dependencies. This takes some minutes.

5. Open <http://localhost:8080> in the browser.
6. To stop the application, press **Ctrl+C** in the PowerShell window.

The output files are in the `data` folder of the project.

## Set up the signer

Do these steps once on the computer that makes the signature. The seminar material
(`Cviko2.zip`) contains the certificate files.

1. Install **D.Suite/eIDAS** from <https://www.slovensko.sk/sk/na-stiahnutie>. Installers exist for
   Windows, macOS and Linux.
2. Install the browser extension **D.Bridge 2**. The installer offers it. Supported browsers:
   Firefox 128 ESR or newer, Chrome and Chromium 136 or newer, Edge 131 or newer.
3. Check the installation on <https://epodpis.ditec.sk/install-check>.
4. Permit the extension to run on local pages. The page <http://localhost:8080> is a local page.
   Open the extension settings in the browser and permit access to `localhost`.
5. Import the test identity. On Windows, double-click `FIITPodpisovatel.pfx` and follow the
   Certificate Import Wizard. Select **Current User**. The password is `test`. Import
   `dtccert.cer` too. It is the certificate of the issuer, *DITEC Test CA SHA256 RSA*.
6. Make a test signature on <https://qes.ditec.sk/upvs/zep/dbridge_js/v1.0/test/dsignerbp.html>.
   If this page works, the application works too.

## Demo

1. Complete the form. Press **Ulož XML**. The file `data/protokol.xml` appears.
2. Press **Over XML voči XSD**. The page shows the result of the validation.
3. Press **Transformuj XML do HTML**. The file `data/protokol.html` appears. Open it with the link.
4. Press **Podpísať**. The application does these steps:
   1. It reads the saved XML, the XSD and the XSLT. It removes the XML declarations.
   2. It transforms the XML with the XSLT and makes a PDF/A-1b file `data/protokol.pdf`.
   3. The page starts D.Signer through D.Bridge JS.
   4. The page adds the XML object. D.Signer puts the XML, the XSD and the XSLT into an
      XMLDataContainer. The schemas are embedded.
   5. The page adds the PDF object.
   6. D.Signer shows both documents. Select the certificate *FIIT Podpisovateľ* and confirm.
   7. The page receives the ASiC-E container as Base64. The server decodes it and writes
      `data/protokol.asice`.
5. Download the container with the link **Stiahnuť ASiC-E**.

To show validation errors, replace the saved file with the invalid sample. Then press the
validate button again:

```bash
cp samples/protokol-chybny.xml data/protokol.xml
```

## Signature parameters

| Parameter | Value | Reason |
|---|---|---|
| Signature format | XAdES-BES in ASiC-E | The assignment asks for this format. |
| `signaturePolicyIdentifier` | empty | A policy identifier makes the signature XAdES-EPES. |
| `digestAlgUri` | SHA-256 | The current recommended algorithm. |
| XMLDataContainer namespace | version 1.1 | The current version of the container schema. |
| `xdcIncludeRefs` | `false` | The XSD and the XSLT are embedded in the container. |
| `xslMediaDestinationTypeDescription` | `XHTML` | The XSLT makes XHTML output. |
| PDF conformance (`pdfUroven`) | `1` = PDF/A-1b | The application makes a PDF/A-1b file. Set `2` in `index.html` if D.Signer refuses the file. |

## Check the output without the application

```bash
xmllint --noout --schema schema/protokol.xsd samples/protokol.xml
xmllint --noout --schema schema/protokol.xsd samples/protokol-chybny.xml
xsltproc -o /tmp/protokol.html schema/protokol.xsl samples/protokol.xml
unzip -l data/protokol.asice
unzip -p data/protokol.asice META-INF/signatures.xml | xmllint --format - | less
pdfinfo data/protokol.pdf
```

The container has these files: `mimetype`, `META-INF/manifest.xml`, `META-INF/signatures.xml`,
the XMLDataContainer and the PDF. The file `signatures.xml` has one `ds:Signature` with one
`ds:Reference` for each object.

## Notes

- XSD 1.0 cannot express rules between fields. The web form applies them: a student younger than
  18 must give a guardian, and the total power is the sum of the appliances.
- The web form prevents most invalid input. The XSD validation on the server is the real check.
- The XSLT makes XHTML, not HTML. The PDF renderer needs well-formed input. Browsers show XHTML
  in the same way.
- The XSLT uses tables for the layout, not flexbox. The PDF renderer and the preview in D.Signer
  do not support flexbox.
