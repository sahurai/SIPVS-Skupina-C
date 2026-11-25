package sk.fiit.sipvs.validator.clients;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import sk.fiit.sipvs.validator.converters.CertificateConverter;

@Component
public class CrlClient {

    private static final Logger log = LoggerFactory.getLogger(CrlClient.class);

    private final HttpClient httpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    public X509CRL download(String url) throws IOException, InterruptedException, GeneralSecurityException {
        log.debug("Downloading CRL {}", url);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20)).GET().build();
        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode());
        }
        X509CRL crl = CertificateConverter.toCrl(response.body());
        log.debug("CRL issued {}, next update {}", crl.getThisUpdate(), crl.getNextUpdate());
        return crl;
    }
}
