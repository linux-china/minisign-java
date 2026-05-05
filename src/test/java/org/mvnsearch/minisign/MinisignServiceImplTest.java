package org.mvnsearch.minisign;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MinisignServiceImplTest {
    private MinisignService service;

    @BeforeAll
    void setUp() {
        service = new MinisignServiceImpl();
    }

    @Test
    void testGenerateKeyPair() throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getSecretKey());
        assertEquals(8, keyPair.getPublicKey().getKeyId().length);
        assertEquals(32, keyPair.getPublicKey().getKeyBytes().length);
        assertEquals(64, keyPair.getSecretKey().getSecretBytes().length);
        assertArrayEquals(keyPair.getPublicKey().getKeyId(), keyPair.getSecretKey().getKeyId());
    }

    @Test
    void testPublicKeyRoundTrip() throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();
        MinisignPublicKey pk = keyPair.getPublicKey();

        String fileContent = pk.toFileContent();
        MinisignPublicKey parsed = MinisignPublicKey.fromFileContent(fileContent);

        assertArrayEquals(pk.getKeyId(), parsed.getKeyId());
        assertArrayEquals(pk.getKeyBytes(), parsed.getKeyBytes());
    }

    @Test
    void testSecretKeyRoundTrip() throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();
        MinisignSecretKey sk = keyPair.getSecretKey();

        String fileContent = sk.toFileContent();
        MinisignSecretKey parsed = MinisignSecretKey.fromFileContent(fileContent);

        assertArrayEquals(sk.getKeyId(), parsed.getKeyId());
        assertArrayEquals(sk.getSecretBytes(), parsed.getSecretBytes());
    }

    @Test()
    void testSaveAndLoadKeyPair() throws Exception {
        MinisignKeyPair generated = service.generateKeyPair();
        service.saveKeyPair(generated);

        MinisignKeyPair loaded = service.loadKeyPair();
        assertArrayEquals(generated.getPublicKey().getKeyId(), loaded.getPublicKey().getKeyId());
        assertArrayEquals(generated.getPublicKey().getKeyBytes(), loaded.getPublicKey().getKeyBytes());
        assertArrayEquals(generated.getSecretKey().getSecretBytes(), loaded.getSecretKey().getSecretBytes());
    }

    @Test
    void testLoadPublicKey() throws Exception {
        MinisignKeyPair generated = service.generateKeyPair();
        service.saveKeyPair(generated);

        MinisignPublicKey loaded = service.loadPublicKey();
        assertArrayEquals(generated.getPublicKey().getKeyId(), loaded.getKeyId());
        assertArrayEquals(generated.getPublicKey().getKeyBytes(), loaded.getKeyBytes());
    }

    @Test
    void testSignAndVerifyBytes() throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();
        byte[] data = "Hello, Minisign!".getBytes();

        MinisignSignature sig = service.sign(data, keyPair.getSecretKey());
        assertTrue(service.verify(data, sig, keyPair.getPublicKey()));
        System.out.println(sig.toFileContent());
    }

    @Test
    void testVerifyFailsOnTamperedData() throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();
        byte[] data = "Original message".getBytes();

        MinisignSignature sig = service.sign(data, keyPair.getSecretKey());
        byte[] tampered = "Tampered message".getBytes();
        assertFalse(service.verify(tampered, sig, keyPair.getPublicKey()));
    }

    @Test
    void testSignAndVerifyFile(@TempDir Path tempDir) throws Exception {
        MinisignKeyPair keyPair = service.generateKeyPair();

        Path testFile = tempDir.resolve("test.txt");
        Files.writeString(testFile, "File content for signing test");

        MinisignSignature sig = service.signFile(testFile, keyPair.getSecretKey());
        assertTrue(service.verifyFile(testFile, sig, keyPair.getPublicKey()));
    }

    @Test
    void testSignatureRoundTrip() throws Exception {
        MinisignKeyPair keyPair = service.loadKeyPair();
        byte[] data = "hello world!".getBytes();

        MinisignSignature sig = service.sign(data, keyPair.getSecretKey());
        String sigContent = sig.toFileContent("signature from minisign secret key");
        System.out.println(sigContent);
        MinisignSignature parsed = MinisignSignature.fromFileContent(sigContent);

        assertTrue(service.verify(data, parsed, keyPair.getPublicKey()));
    }

    @Test
    void testVerifyFailsWithWrongKey() throws Exception {
        MinisignKeyPair keyPair1 = service.generateKeyPair();
        MinisignKeyPair keyPair2 = service.generateKeyPair();
        byte[] data = "Test data".getBytes();

        MinisignSignature sig = service.sign(data, keyPair1.getSecretKey());
        assertFalse(service.verify(data, sig, keyPair2.getPublicKey()));
    }

    @Test
    void testBlake2b256() {
        // BLAKE2b-256 of empty input: known test vector
        byte[] result = Blake2b.hash256(new byte[0]);
        assertEquals(32, result.length);
        // Known hash of empty string with BLAKE2b-256:
        // 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        String hex = bytesToHex(result);
        assertEquals("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", hex);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Test
    public void testLoadKeyPair() throws Exception {
        final MinisignKeyPair keyPair = service.loadKeyPair();
        MinisignSecretKey privateKey = keyPair.getSecretKey();
        MinisignPublicKey publicKey = keyPair.getPublicKey();
        System.out.println(privateKey.toFileContent());
        System.out.println(publicKey.toFileContent());
    }

}
