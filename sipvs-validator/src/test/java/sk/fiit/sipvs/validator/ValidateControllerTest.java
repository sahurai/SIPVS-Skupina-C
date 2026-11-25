package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import sk.fiit.sipvs.validator.clients.CrlClient;
import sk.fiit.sipvs.validator.controllers.ValidateController;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.services.ValidationService;
import sk.fiit.sipvs.validator.services.steps.AlgorithmValidator;
import sk.fiit.sipvs.validator.services.steps.CertificateTrustValidator;
import sk.fiit.sipvs.validator.services.steps.CoreValidator;
import sk.fiit.sipvs.validator.services.steps.DataObjectValidator;
import sk.fiit.sipvs.validator.services.steps.ProfileValidator;
import sk.fiit.sipvs.validator.services.steps.QualifyingPropertiesValidator;
import sk.fiit.sipvs.validator.services.steps.SignatureStructureValidator;
import sk.fiit.sipvs.validator.services.steps.SigningCertificateValidator;
import sk.fiit.sipvs.validator.services.steps.TimestampValidator;
import sk.fiit.sipvs.validator.services.steps.XmlDataContainerValidator;
import sk.fiit.sipvs.validator.utils.MessageUtil;
import sk.fiit.sipvs.validator.utils.TrustAnchorUtil;

@WebMvcTest(ValidateController.class)
@Import({ValidationService.class, ProfileValidator.class, AlgorithmValidator.class, SignatureStructureValidator.class,
        QualifyingPropertiesValidator.class, DataObjectValidator.class, XmlDataContainerValidator.class,
        SigningCertificateValidator.class, CertificateTrustValidator.class, TimestampValidator.class, CoreValidator.class,
        MessageUtil.class, CrlClient.class, TrustAnchorUtil.class})
class ValidateControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoSpyBean
    private ValidationService validationService;

    @Test
    void multipleFiles() throws Exception {
        doNothing().when(validationService).validateSignature(any());
        byte[] sample = new ClassPathResource("samples/01X-T.asice").getContentAsByteArray();
        mvc.perform(multipart("/api/validate")
                        .file(new MockMultipartFile("file", "01X-T.asice", "application/vnd.etsi.asic-e+zip", sample))
                        .file(new MockMultipartFile("file", "b.asice", "application/vnd.etsi.asic-e+zip", new byte[0]))
                        .file(new MockMultipartFile("file", "c.xml", "text/xml", "<a/>".getBytes())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].name").value("01X-T.asice"))
                .andExpect(jsonPath("$.files[0].size").value(sample.length))
                .andExpect(jsonPath("$.files[0].error").doesNotExist())
                .andExpect(jsonPath("$.files[1].size").doesNotExist())
                .andExpect(jsonPath("$.files[1].error").value("b.asice: je prázdny"))
                .andExpect(jsonPath("$.files[2].error").value("c.xml: nie je správny"));
    }

    // MAX_VALIDATIONS files wait in validateSignature, so one more file fails at once with the retry message.
    @Test
    void fileFailsWhenAllValidationsRun() throws Exception {
        CountDownLatch started = new CountDownLatch(ValidationService.MAX_VALIDATIONS);
        CountDownLatch finish = new CountDownLatch(1);
        doAnswer(invocation -> {
            started.countDown();
            finish.await(10, TimeUnit.SECONDS);
            return null;
        }).when(validationService).validateSignature(any());
        MockMultipartFile file = new MockMultipartFile("file", "a.asice", "application/vnd.etsi.asic-e+zip", new byte[] {1});
        List<Thread> threads = new ArrayList<>();
        try {
            for (int i = 0; i < ValidationService.MAX_VALIDATIONS; i++) {
                Thread thread = new Thread(() -> validationService.validate(List.of(file)));
                thread.start();
                threads.add(thread);
            }
            assertTrue(started.await(10, TimeUnit.SECONDS));
            mvc.perform(multipart("/api/validate").file(file))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.files[0].error").value("Súbor: nie je dostupný. Server práve overuje najväčší povolený počet "
                            + "súborov naraz (" + ValidationService.MAX_VALIDATIONS + "), overte súbor znova neskôr."));
        } finally {
            finish.countDown();
            for (Thread thread : threads) {
                thread.join(10_000);
            }
        }
        mvc.perform(multipart("/api/validate").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].error").doesNotExist());
    }

    @Test
    void noFile() throws Exception {
        mvc.perform(multipart("/api/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Súbor: nie je zadaný"));
    }

    @Test
    void notMultipart() throws Exception {
        mvc.perform(post("/api/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Súbor: nie je zadaný"));
    }

    @Test
    void signatureError() throws Exception {
        doThrow(new AttributeException("ds:SignatureMethod", State.NOT_CORRECT))
                .when(validationService).validateSignature(any());
        mvc.perform(multipart("/api/validate")
                        .file(new MockMultipartFile("file", "03X-T.asice", "application/vnd.etsi.asic-e+zip", new byte[] {1})))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].error").value("ds:SignatureMethod: nie je správny"));
    }

    @Test
    void unexpectedErrorInOneFile() throws Exception {
        doThrow(new IllegalStateException("boom"))
                .when(validationService).validateSignature(any());
        mvc.perform(multipart("/api/validate")
                        .file(new MockMultipartFile("file", "01X-T.asice", "application/vnd.etsi.asic-e+zip", new byte[] {1}))
                        .file(new MockMultipartFile("file", "c.xml", "text/xml", "<a/>".getBytes())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].error").value("Nastala neočakávaná chyba."))
                .andExpect(jsonPath("$.files[1].error").value("c.xml: nie je správny"));
    }

    // An Error such as StackOverflowError is also reported for its file, not as HTTP 500.
    @Test
    void errorInOneFile() throws Exception {
        doThrow(new StackOverflowError())
                .when(validationService).validateSignature(any());
        mvc.perform(multipart("/api/validate")
                        .file(new MockMultipartFile("file", "01X-T.asice", "application/vnd.etsi.asic-e+zip", new byte[] {1})))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].error").value("Nastala neočakávaná chyba."));
    }
}
