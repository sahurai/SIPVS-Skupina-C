package sk.fiit.sipvs.validator.converters;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.xml.XMLConstants;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.URIResolver;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.w3c.dom.Document;


public final class XsltConverter {

    public static final int MAX_OUTPUT = 5_000_000;
    public static final int TIMEOUT_SECONDS = 5;
    public static final int MAX_THREADS = 4;

    private static final ExecutorService EXECUTOR = new ThreadPoolExecutor(0, MAX_THREADS, 60, TimeUnit.SECONDS,
        new SynchronousQueue<>(), task -> {
            Thread thread = new Thread(task, "xslt");
            thread.setDaemon(true);
            return thread;
        });

    private XsltConverter() {}

    public static String transform(Document stylesheet, Document data) throws XsltException {
        Future<String> future;
        try {
            future = EXECUTOR.submit(() -> run(stylesheet, data));
        } catch (RejectedExecutionException e) {
            throw new XsltException(Reason.BUSY, String.valueOf(MAX_THREADS));
        }
        try {
            return future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new XsltException(Reason.TIMEOUT, String.valueOf(TIMEOUT_SECONDS));
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new XsltException(Reason.FAILED, e.getClass().getSimpleName());
        } catch (ExecutionException e) {
            if (e.getCause() instanceof XsltException failure) {
                throw failure;
            }
            throw new IllegalStateException(e.getCause());
        }
    }

    private static String run(Document stylesheet, Document data) throws XsltException {
        List<String> blocked = new ArrayList<>();
        URIResolver resolver = (href, base) -> {
            blocked.add(href);
            throw new TransformerException("External resource not allowed: " + href);
        };
        LimitedWriter output = new LimitedWriter();
        try {
            TransformerFactory factory = TransformerFactory.newDefaultInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, StringUtils.EMPTY);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, StringUtils.EMPTY);
            factory.setURIResolver(resolver);
            factory.setErrorListener(FailingListener.INSTANCE);
            Transformer transformer = factory.newTemplates(new DOMSource(stylesheet)).newTransformer();
            transformer.setURIResolver(resolver);
            transformer.setErrorListener(FailingListener.INSTANCE);
            transformer.transform(new DOMSource(data), new StreamResult(output));
        } catch (TransformerException | RuntimeException | StackOverflowError | OutOfMemoryError e) {
            throw failure(blocked, output, e);
        }
        // The processor reports a failed document() call to the error listener and may go on without the document.
        if (!blocked.isEmpty()) {
            throw new XsltException(Reason.EXTERNAL_REFERENCE, blocked.get(0));
        }
        return output.text.toString();
    }

    private static XsltException failure(List<String> blocked, LimitedWriter output, Throwable e) {
        if (!blocked.isEmpty()) {
            return new XsltException(Reason.EXTERNAL_REFERENCE, blocked.get(0));
        }
        if (output.full) {
            return new XsltException(Reason.TOO_LARGE, String.valueOf(MAX_OUTPUT));
        }
        if (e instanceof Error) {
            return new XsltException(Reason.FAILED, e.getClass().getSimpleName());
        }
        String message = e instanceof TransformerConfigurationException ? e.getMessage() : ExceptionUtils.getRootCauseMessage(e);
        return new XsltException(Reason.FAILED, Strings.CS.removeEnd(StringUtils.normalizeSpace(message), "."));
    }

    public enum Reason {
        EXTERNAL_REFERENCE,
        TOO_LARGE,
        TIMEOUT,
        BUSY,
        FAILED
    }

    public static final class XsltException extends Exception {

        private final Reason reason;
        private final String value;

        private XsltException(Reason reason, String value) {
            super(reason + ": " + value);
            this.reason = reason;
            this.value = value;
        }

        public Reason getReason() {
            return reason;
        }

        public String getValue() {
            return value;
        }
    }

    private static final class LimitedWriter extends Writer {

        private final StringBuilder text = new StringBuilder();
        private boolean full;

        @Override
        public void write(char[] chars, int offset, int length) throws IOException {
            if (text.length() + length > MAX_OUTPUT) {
                full = true;
                throw new IOException("XSLT output is larger than " + MAX_OUTPUT + " characters");
            }
            text.append(chars, offset, length);
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    }

    private enum FailingListener implements ErrorListener {
        INSTANCE;

        @Override
        public void warning(TransformerException e) {}

        @Override
        public void error(TransformerException e) throws TransformerException {
            throw e;
        }

        @Override
        public void fatalError(TransformerException e) throws TransformerException {
            throw e;
        }
    }
}
