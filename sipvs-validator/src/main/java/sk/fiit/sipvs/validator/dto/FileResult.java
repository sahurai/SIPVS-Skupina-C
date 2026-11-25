package sk.fiit.sipvs.validator.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record FileResult(String name, Long size, String error, Location location) {

    public static FileResult ok(String name, long size) {
        return new FileResult(name, size, null, null);
    }

    public static FileResult error(String name, String error) {
        return new FileResult(name, null, error, null);
    }

    public static FileResult error(String name, String error, Location location) {
        return new FileResult(name, null, error, location);
    }
}
