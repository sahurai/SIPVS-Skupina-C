# SIPVS – zadanie 1: Ubytovací protokol (ŠD Mladosť)

The check-in protocol of the Mladosť dormitory as an XML form. The student fills it in on arrival.
The dormitory system already assigns the room, so the form does not contain it.

## Files

| Path | Purpose |
|---|---|
| `schema/protokol.xsd` | structure of the form, namespace `urn:mladost:ubytovaci-protokol:1.0` |
| `schema/protokol.xsl` | XSLT 1.0 transformation to a print-like HTML page |
| `samples/protokol.xml` | a valid instance |
| `samples/protokol-chybny.xml` | an instance with eight deliberate errors |
| `src/main/resources/static/index.html` | the web form, Bootstrap 5 served from the `org.webjars:bootstrap` dependency, so it works offline |
| `src/main/java/sk/fiit/sipvs/XmlService.java` | the three operations, JDK classes only |
| `data/` | output of the application (`protokol.xml`, `protokol.html`), not in git |

## How the XSD meets the assignment

- **Data types:** `xs:string`, `xs:date`, `xs:boolean`, `xs:positiveInteger`, `xs:base64Binary`,
  plus restricted types with patterns, enumerations and ranges.
- **Repeating section:** `spotrebic` inside `spotrebice`, at most 5.
- **Attributes:** `univerzitneId` on `student`, `typ` on `spotrebic` and on `fotografia`.
- **Namespace:** `urn:mladost:ubytovaci-protokol:1.0`, `elementFormDefault="qualified"`.

## Run

The project needs JDK 17 or newer. The Maven wrapper downloads Maven on the first run.

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ./mvnw spring-boot:run
```

On Arch Linux the default `java` may be an older version. Either set `JAVA_HOME` as above
or switch the default with `archlinux-java set java-17-openjdk`.

Open <http://localhost:8080>.

## Demo

1. Fill in the form and press **Ulož XML**. The file `data/protokol.xml` appears.
2. Press **Over XML voči XSD**. The page shows the result of validation.
3. Press **Transformuj XML do HTML**. The file `data/protokol.html` appears; open it with the link.

To show validation errors, replace the saved file with the invalid sample and press the
validate button again:

```bash
cp samples/protokol-chybny.xml data/protokol.xml
```

## Checks without the application

```bash
xmllint --noout --schema schema/protokol.xsd samples/protokol.xml
xmllint --noout --schema schema/protokol.xsd samples/protokol-chybny.xml
xsltproc -o /tmp/protokol.html schema/protokol.xsl samples/protokol.xml
```

## Notes

- XSD 1.0 cannot express rules between fields. The web form enforces them: a student younger
  than 18 must give a guardian, the total power is the sum of the appliances.
- The web form prevents most invalid input. The server-side XSD validation is the real check.
