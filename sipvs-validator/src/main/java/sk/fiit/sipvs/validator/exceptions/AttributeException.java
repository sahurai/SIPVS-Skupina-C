package sk.fiit.sipvs.validator.exceptions;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import org.w3c.dom.Node;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;

public class AttributeException extends RuntimeException {

    private final String attribute;
    private final State state;
    private final Detail detail;
    private final String[] args;
    private transient Node node;
    private String file;
    private String content;

    public AttributeException(String attribute, State state) {
        this(attribute, state, null);
    }

    public AttributeException(String attribute, State state, Detail detail, Object... args) {
        super(attribute + ": " + state + (detail == null ? "" : " " + detail));
        this.attribute = attribute;
        this.state = state;
        this.detail = detail;
        this.args = Arrays.stream(args).map(AttributeException::text).toArray(String[]::new);
    }

    private static String text(Object value) {
        if (value instanceof Date date) {
            return date.toInstant().toString();
        }
        if (value instanceof Instant instant) {
            return instant.toString();
        }
        return String.valueOf(value);
    }

    public AttributeException at(Node node) {
        this.node = node;
        return this;
    }

    public AttributeException in(String file, String content) {
        if (this.file == null) {
            this.file = file;
            this.content = content;
        }
        return this;
    }

    public Node getNode() {
        return node;
    }

    public String getFile() {
        return file;
    }

    public String getContent() {
        return content;
    }


    public String getAttribute() {
        return attribute;
    }

    public State getState() {
        return state;
    }

    public Detail getDetail() {
        return detail;
    }

    public String[] getArgs() {
        return args.clone();
    }
}
