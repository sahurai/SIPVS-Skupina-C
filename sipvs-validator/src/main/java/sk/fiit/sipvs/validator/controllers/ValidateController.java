package sk.fiit.sipvs.validator.controllers;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import sk.fiit.sipvs.validator.dto.ValidateResponse;
import sk.fiit.sipvs.validator.services.ValidationService;

@RestController
public class ValidateController {

    private static final Logger log = LoggerFactory.getLogger(ValidateController.class);

    private final ValidationService validationService;

    public ValidateController(ValidationService validationService) {
        this.validationService = validationService;
    }

    @PostMapping("/api/validate")
    public ResponseEntity<ValidateResponse> validate(
        @RequestParam(name = "file", required = false) List<MultipartFile> files) {
        log.info("Validate request with {} file(s)", files == null ? 0 : files.size());
        return ResponseEntity.ok(new ValidateResponse(validationService.validate(files)));
    }
}
