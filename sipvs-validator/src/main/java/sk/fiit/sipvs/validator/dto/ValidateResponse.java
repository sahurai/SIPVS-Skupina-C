package sk.fiit.sipvs.validator.dto;

import java.util.List;

public record ValidateResponse(List<FileResult> files) { }
