<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:p="urn:mladost:ubytovaci-protokol:1.0"
    exclude-result-prefixes="p">

  <xsl:output method="html" encoding="UTF-8" indent="yes" doctype-system="about:legacy-compat"/>

  <xsl:template match="/p:ubytovaciProtokol">
    <html lang="sk">
      <head>
        <title>Ubytovací protokol – <xsl:value-of select="concat(p:student/p:meno, ' ', p:student/p:priezvisko)"/></title>
        <style>
          @page { size: A4; margin: 15mm; }
          body { margin: 0; background: #e5e5e5; color: #000; font: 11pt/1.4 "Times New Roman", Georgia, serif; }
          .list { box-sizing: border-box; width: 210mm; min-height: 297mm; margin: 0 auto; padding: 15mm 18mm; background: #fff; }
          @media print { body { background: #fff; } .list { width: auto; min-height: 0; margin: 0; padding: 0; } }
          .hlavicka { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid #000; padding-bottom: 6pt; }
          .org { font-size: 9pt; text-transform: uppercase; letter-spacing: .04em; }
          h1 { margin: 14pt 0 2pt; font-size: 18pt; text-align: center; letter-spacing: .06em; }
          .podtitul { margin: 0 0 14pt; text-align: center; font-size: 10pt; }
          h2 { margin: 14pt 0 6pt; padding-bottom: 2pt; border-bottom: 1px solid #000; font-size: 11pt; text-transform: uppercase; }
          .udaje { width: 100%; border-collapse: collapse; }
          .udaje th { width: 34%; padding: 3pt 4pt; text-align: left; font-weight: normal; color: #333; vertical-align: top; }
          .udaje td { padding: 3pt 4pt; border-bottom: 1px dotted #999; vertical-align: top; }
          .student { display: flex; gap: 10mm; align-items: flex-start; }
          .student .udaje { flex: 1; }
          .foto { flex: none; width: 35mm; height: 45mm; border: 1px solid #000; object-fit: cover; }
          .foto-prazdna { display: flex; align-items: center; justify-content: center; color: #888; font-size: 9pt; }
          .tabulka { width: 100%; border-collapse: collapse; margin-top: 4pt; }
          .tabulka th, .tabulka td { border: 1px solid #000; padding: 3pt 5pt; }
          .tabulka th { background: #eee; font-weight: normal; font-size: 9.5pt; }
          .tabulka tfoot td { font-weight: bold; }
          .c { text-align: center; }
          .r { text-align: right; }
          .box { margin-right: 4pt; font-size: 13pt; }
          .podpisy { display: flex; gap: 10mm; margin-top: 32pt; }
          .podpis { flex: 1; padding-top: 3pt; border-top: 1px solid #000; text-align: center; font-size: 9pt; }
        </style>
      </head>
      <body>
        <div class="list">
          <div class="hlavicka">
            <div>
              <div class="org">Slovenská technická univerzita v Bratislave</div>
              <div class="org">Študentský domov Mladosť</div>
            </div>
            <div class="org">Univerzitné ID: <xsl:value-of select="p:student/@univerzitneId"/></div>
          </div>

          <h1>Ubytovací protokol</h1>
          <p class="podtitul">protokol o nástupe študenta na ubytovanie</p>

          <h2>1. Ubytovaný študent</h2>
          <div class="student">
            <table class="udaje">
              <tr><th>Meno a priezvisko</th><td><xsl:value-of select="concat(p:student/p:meno, ' ', p:student/p:priezvisko)"/></td></tr>
              <tr><th>Dátum narodenia</th><td><xsl:call-template name="datum"><xsl:with-param name="d" select="p:student/p:datumNarodenia"/></xsl:call-template></td></tr>
              <tr><th>Štátna príslušnosť</th><td><xsl:value-of select="p:student/p:statnaPrislusnost"/></td></tr>
              <tr><th>Fakulta</th><td><xsl:value-of select="p:student/p:fakulta"/></td></tr>
              <tr><th>Ročník</th><td><xsl:value-of select="p:student/p:rocnik"/>.</td></tr>
              <tr><th>Telefón</th><td><xsl:call-template name="volitelne"><xsl:with-param name="v" select="p:student/p:telefon"/></xsl:call-template></td></tr>
              <tr><th>E-mail</th><td><xsl:call-template name="volitelne"><xsl:with-param name="v" select="p:student/p:email"/></xsl:call-template></td></tr>
              <xsl:if test="p:student/p:zakonnyZastupca">
                <tr><th>Zákonný zástupca</th><td><xsl:value-of select="p:student/p:zakonnyZastupca"/></td></tr>
              </xsl:if>
            </table>
            <xsl:choose>
              <xsl:when test="p:student/p:fotografia">
                <img class="foto" alt="Fotografia študenta"
                     src="data:{p:student/p:fotografia/@typ};base64,{translate(p:student/p:fotografia, ' &#10;&#13;&#9;', '')}"/>
              </xsl:when>
              <xsl:otherwise>
                <div class="foto foto-prazdna">fotografia</div>
              </xsl:otherwise>
            </xsl:choose>
          </div>

          <h2>2. Trvalé bydlisko</h2>
          <table class="udaje">
            <tr><th>Ulica a číslo</th><td><xsl:value-of select="concat(p:adresa/p:ulica, ' ', p:adresa/p:cislo)"/></td></tr>
            <tr><th>PSČ a mesto</th><td><xsl:value-of select="concat(p:adresa/p:psc, ' ', p:adresa/p:mesto)"/></td></tr>
            <tr><th>Štát</th><td><xsl:value-of select="p:adresa/p:stat"/></td></tr>
          </table>

          <h2>3. Elektrické spotrebiče prihlásené na izbe</h2>
          <xsl:choose>
            <xsl:when test="p:spotrebice/p:spotrebic">
              <table class="tabulka">
                <thead>
                  <tr><th class="c">P. č.</th><th>Typ</th><th>Značka</th><th>Sériové číslo</th><th class="r">Príkon (W)</th></tr>
                </thead>
                <tbody>
                  <xsl:for-each select="p:spotrebice/p:spotrebic">
                    <tr>
                      <td class="c"><xsl:value-of select="position()"/>.</td>
                      <td><xsl:call-template name="typSpotrebica"><xsl:with-param name="kod" select="@typ"/></xsl:call-template></td>
                      <td><xsl:value-of select="p:znacka"/></td>
                      <td><xsl:value-of select="p:serioveCislo"/></td>
                      <td class="r"><xsl:value-of select="p:prikon"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
                <tfoot>
                  <tr><td colspan="4">Celkový príkon</td><td class="r"><xsl:value-of select="p:spotrebice/p:celkovyPrikon"/></td></tr>
                </tfoot>
              </table>
            </xsl:when>
            <xsl:otherwise>
              <p>Študent neprihlasuje žiadne elektrické spotrebiče.</p>
            </xsl:otherwise>
          </xsl:choose>

          <h2>4. Vyhlásenie</h2>
          <p>
            <span class="box">
              <xsl:choose>
                <xsl:when test="p:potvrdenie/p:suhlas = 'true' or p:potvrdenie/p:suhlas = '1'">&#9746;</xsl:when>
                <xsl:otherwise>&#9744;</xsl:otherwise>
              </xsl:choose>
            </span>
            Vyhlasujem, že uvedené údaje sú pravdivé a úplné a že som sa oboznámil/a s ubytovacím poriadkom Študentského domova Mladosť.
          </p>
          <p>V Bratislave dňa <xsl:call-template name="datum"><xsl:with-param name="d" select="p:potvrdenie/p:datumVyplnenia"/></xsl:call-template></p>

          <div class="podpisy">
            <div class="podpis">podpis študenta</div>
            <xsl:if test="p:student/p:zakonnyZastupca">
              <div class="podpis">podpis zákonného zástupcu</div>
            </xsl:if>
            <div class="podpis">za ubytovateľa</div>
          </div>
        </div>
      </body>
    </html>
  </xsl:template>

  <xsl:template name="datum">
    <xsl:param name="d"/>
    <xsl:value-of select="concat(substring($d, 9, 2), '.', substring($d, 6, 2), '.', substring($d, 1, 4))"/>
  </xsl:template>

  <xsl:template name="volitelne">
    <xsl:param name="v"/>
    <xsl:choose>
      <xsl:when test="$v"><xsl:value-of select="$v"/></xsl:when>
      <xsl:otherwise>–</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="typSpotrebica">
    <xsl:param name="kod"/>
    <xsl:choose>
      <xsl:when test="$kod = 'chladnicka'">chladnička</xsl:when>
      <xsl:when test="$kod = 'mikrovlnnaRura'">mikrovlnná rúra</xsl:when>
      <xsl:when test="$kod = 'rychlovarnaKanvica'">rýchlovarná kanvica</xsl:when>
      <xsl:when test="$kod = 'kavovar'">kávovar</xsl:when>
      <xsl:otherwise>iné</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
