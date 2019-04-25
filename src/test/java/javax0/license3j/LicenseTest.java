package javax0.license3j;

import javax0.license3j.Feature;
import javax0.license3j.License;
import javax0.license3j.crypto.LicenseKeyPair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.UUID;

class LicenseTest {

    @Test
    @DisplayName("Creates a license and then it can access the features.")
    void createLicenseViaAPI() {
        final License sut = new License();
        final Date now = new Date(1545047719295L);
        addSampleFeatures(sut, now);
        Assertions.assertEquals("Peter Verhas", sut.get("owner").getString());
        Assertions.assertEquals(now, sut.get("expiry").getDate());
    }

    private void addSampleFeatures(License sut, Date now) {
        sut.add(Feature.Create.stringFeature("owner", "Peter Verhas"));
        sut.add(Feature.Create.stringFeature("title", "A license test, \ntest license"));
        sut.add(Feature.Create.dateFeature("expiry", now));
        sut.add(Feature.Create.stringFeature("template", "<<special template>>"));
    }

    @Test
    @DisplayName("Create a license with features serialize and restore then the features are the same")
    void licenseSerializeAndDeserialize() {
        final License sut = new License();
        final Date now = new Date(1545047719295L);
        addSampleFeatures(sut, now);
        byte[] buffer = sut.serialized();
        final License restored = License.Create.from(buffer);
        Assertions.assertEquals("Peter Verhas", restored.get("owner").getString());
        Assertions.assertEquals(now, restored.get("expiry").getDate());
        Assertions.assertEquals("expiry:DATE=2018-12-17 12:55:19.295\n" +
                "owner=Peter Verhas\n" +
                "template=<<null\n" +
                "<<special template>>\n" +
                "null\n" +
                "title=<<B\n" +
                "A license test, \n" +
                "test license\n" +
                "B\n", sut.toString());
    }

    @Test
    @DisplayName("Create a license with features convert to string and restore then the features are the same")
    void licenseStringifyAndDestringify() {
        final License sut = new License();
        final Date now = new Date(1545047719295L);
        addSampleFeatures(sut, now);
        String string = sut.toString();
        final License restored = License.Create.from(string);
        Assertions.assertEquals("Peter Verhas", restored.get("owner").getString());
        Assertions.assertEquals(now, restored.get("expiry").getDate());
        Assertions.assertEquals("expiry:DATE=2018-12-17 12:55:19.295\n" +
                "owner=Peter Verhas\n" +
                "template=<<null\n" +
                "<<special template>>\n" +
                "null\n" +
                "title=<<B\n" +
                "A license test, \n" +
                "test license\n" +
                "B\n", sut.toString());
    }

    @Test
    @DisplayName("Test that the fingerprint does not change even if we change the signature algorithm")
    void testLicenseFingerprint() throws NoSuchAlgorithmException, IllegalBlockSizeException,
        InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        final License sut = new License();
        final Date now = new Date(1545047719295L);
        addSampleFeatures(sut, now);
        final UUID fpUnsigned = sut.fingerprint();
        LicenseKeyPair keysRSA1024 = LicenseKeyPair.Create.from("RSA",  1000);
        sut.sign(keysRSA1024.getPair().getPrivate(), "SHA-512");
        final UUID fpSignedSHA512 = sut.fingerprint();
        LicenseKeyPair keysRSA4096 = LicenseKeyPair.Create.from("RSA", 4096);
        sut.sign(keysRSA4096.getPair().getPrivate(), "MD5");
        final UUID fpSignedMD5 = sut.fingerprint();
        Assertions.assertEquals(fpUnsigned,fpSignedSHA512);
        Assertions.assertEquals(fpUnsigned,fpSignedMD5);
    }

    @Test
    @DisplayName("A license with an expiry date a day ago has expired")
    void pastExpiryTimeReportsExpired() {
        final License license = new License();
        license.setExpiry(new Date(new Date().getTime() - 24 * 60 * 60 * 1000));
        Assertions.assertTrue(license.isExpired());
    }

    @Test
    @DisplayName("A license with an expiry date a day ahead has not expired")
    void futureExpiryTimeReportsNonExpired()  {
        final License lic = new License();
        lic.setExpiry(new Date(new Date().getTime() + 24 * 60 * 60 * 1000));
        Assertions.assertFalse(lic.isExpired());
    }

    @Test
    void uuidGenerationResultsNonNullUuid() {
        final License lic = new License();
        lic.setLicenseId();
        Assertions.assertNotNull(lic.getLicenseId());
    }

}
