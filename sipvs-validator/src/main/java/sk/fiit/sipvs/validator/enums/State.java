package sk.fiit.sipvs.validator.enums;

public enum State {
    NOT_PROVIDED,
    NOT_CORRECT,
    EMPTY,
    TOO_LARGE,
    NOT_AVAILABLE;

    public String key() {
        return "state." + name();
    }
}
