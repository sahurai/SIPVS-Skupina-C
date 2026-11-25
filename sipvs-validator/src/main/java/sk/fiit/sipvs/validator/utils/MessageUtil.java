package sk.fiit.sipvs.validator.utils;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;

@Component
public class MessageUtil {

    private final MessageSource messageSource;

    public MessageUtil(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    public String error(AttributeException e) {
        String message = error(e.getAttribute(), e.getState());
        if (e.getDetail() != null) {
            message = text("error.detail", message, text(e.getDetail().key(), (Object[]) e.getArgs()));
        }
        return message;
    }

    public String error(String attribute, State state) {
        String name = messageSource.getMessage("attribute." + attribute, null, attribute, LocaleContextHolder.getLocale());
        return text("error.format", name, text(state.key()));
    }

    public String text(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }
}
