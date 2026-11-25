package sk.fiit.sipvs.validator.exceptions;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.MessageUtil;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final MessageUtil messages;

    public GlobalExceptionHandler(MessageUtil messages) {
        this.messages = messages;
    }

    @ExceptionHandler(AttributeException.class)
    public ResponseEntity<Map<String, String>> handleAttribute(AttributeException e) {
        return respond(HttpStatus.BAD_REQUEST, messages.error(e));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, String>> handleTooLarge(MaxUploadSizeExceededException e) {
        return respond(HttpStatus.CONTENT_TOO_LARGE, messages.error("file", State.TOO_LARGE));
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<Map<String, String>> handleMultipart(MultipartException e) {
        return respond(HttpStatus.BAD_REQUEST, messages.error("request", State.NOT_CORRECT));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleUnexpected(Exception e) {
        if (e instanceof ErrorResponse response) {
            return ResponseEntity.status(response.getStatusCode()).build();
        }
        log.error("Unexpected error", e);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, messages.text("error.unexpected"));
    }

    private static ResponseEntity<Map<String, String>> respond(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of("error", message));
    }
}
