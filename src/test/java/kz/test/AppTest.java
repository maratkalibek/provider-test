package kz.test;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.provider.utils.CMSUtil;
import kz.gov.pki.provider.utils.KeyStoreUtil;
import kz.gov.pki.provider.utils.model.SigningEntity;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

import static org.junit.Assert.assertNotNull;

public class AppTest {

    @Before
    public void init() {
        Security.addProvider(new KalkanProvider());
    }

    @Test
    public void testSign() throws Exception {
        byte [] keyData = IOUtils.resourceToByteArray("/RSA256_11c707bd54cbfcccb3815e39c4eb57b1dc7dfea9.p12");
        String password = "Qwerty12";

        byte [] dataToSign = IOUtils.resourceToByteArray("/sample.bin");

        KeyStore keyStore = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
        keyStore.load(new ByteArrayInputStream(keyData), password.toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        String alias = aliases.nextElement();

        SigningEntity entity = KeyStoreUtil.getSigningEntity(keyStore, alias, password.toCharArray());
        CMSSignedData signedData = CMSUtil.createCAdES(entity, dataToSign, false, Security.getProvider(KalkanProvider.PROVIDER_NAME));

        assertNotNull(signedData);
    }
}
