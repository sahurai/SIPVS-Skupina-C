package sk.fiit.sipvs.validator.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import sk.fiit.sipvs.validator.enums.Mark;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Location(String file, String path, Mark mark, String attribute, String content) { }
