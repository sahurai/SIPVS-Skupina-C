package sk.fiit.sipvs;

import java.util.List;
import java.util.Map;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ProtokolController {

    private final XmlService xml;
    private final PodpisService podpis;

    public ProtokolController(XmlService xml, PodpisService podpis) {
        this.xml = xml;
        this.podpis = podpis;
    }

    @PostMapping("/uloz-xml")
    public Map<String, Object> ulozXml(@RequestBody Protokol protokol) throws Exception {
        return Map.of("subor", xml.ulozXml(protokol).toString());
    }

    @PostMapping("/over-xml")
    public Map<String, Object> overXml() throws Exception {
        List<String> chyby = xml.overXml();
        return Map.of("subor", xml.xmlSubor().toString(), "platny", chyby.isEmpty(), "chyby", chyby);
    }

    @PostMapping("/transformuj-xml")
    public Map<String, Object> transformujXml() throws Exception {
        return Map.of("subor", xml.transformujXml().toString(), "url", "/api/vystup/protokol.html");
    }

    @GetMapping("/podpis-vstupy")
    public PodpisService.Vstupy podpisVstupy() throws Exception {
        return podpis.vstupy();
    }

    @PostMapping("/uloz-podpis")
    public Map<String, Object> ulozPodpis(@RequestBody Map<String, String> telo) throws Exception {
        return Map.of("subor", podpis.ulozAsice(telo.get("asice")).toString(), "url", "/api/vystup/protokol.asice");
    }

    @GetMapping(value = "/vystup/protokol.pdf", produces = "application/pdf")
    public Resource vystupPdf() {
        return new FileSystemResource(podpis.pdfSubor());
    }

    @GetMapping(value = "/vystup/protokol.asice", produces = "application/vnd.etsi.asic-e+zip")
    public ResponseEntity<Resource> vystupAsice() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"protokol.asice\"")
                .body(new FileSystemResource(podpis.asiceSubor()));
    }

    @GetMapping(value = "/vystup/protokol.xml", produces = "application/xml;charset=UTF-8")
    public Resource vystupXml() {
        return new FileSystemResource(xml.xmlSubor());
    }

    @GetMapping(value = "/vystup/protokol.html", produces = "text/html;charset=UTF-8")
    public Resource vystupHtml() {
        return new FileSystemResource(xml.htmlSubor());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> chyba(Exception e) {
        return ResponseEntity.internalServerError().body(Map.of("chyba", String.valueOf(e.getMessage())));
    }
}
