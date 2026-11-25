package sk.fiit.sipvs.validator.converters;

import java.io.IOException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

public final class TimestampConverter {

    private TimestampConverter() {}

    public static TimeStampToken toToken(byte[] der) throws CMSException, TSPException, IOException {
        return new TimeStampToken(new CMSSignedData(der));
    }
}
