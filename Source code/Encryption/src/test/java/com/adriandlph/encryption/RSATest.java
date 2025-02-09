
package com.adriandlph.encryption;

import com.adriandlph.encryption.algorithms.RSA;
import java.security.Key;
import java.security.KeyPair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 * @author adriandlph
 *
 */
public class RSATest {
	
    @Test
    public void testKeyPairGeneration() {
		KeyPair keyPair;
		int keySize = 1024;
		byte[] encoded;
		Key key;
		
		keyPair = RSA.generateKeyPair(keySize);
		
        Assertions.assertNotNull(keyPair);
		
		key = keyPair.getPublic();
		Assertions.assertEquals("RSA", key.getAlgorithm());
		encoded = key.getEncoded();
		Assertions.assertNotNull(encoded);
		
		key = keyPair.getPrivate();
		Assertions.assertEquals("RSA", key.getAlgorithm());
		encoded = key.getEncoded();
		Assertions.assertNotNull(encoded);
    }
	
	@Test
    public void testKeyPairSaveAndLoad() {
		KeyPair keyPair, keyPairLoaded;
		int keySize = 1024;
		byte[] encoded;
		Key key;
		
		keyPair = RSA.generateKeyPair(keySize);
		
		Assertions.assertTrue(RSA.saveKeyPair(keyPair, "public.key", "private.key"));
		
		keyPairLoaded = RSA.loadKeyPair("public.key", "private.key");
        Assertions.assertNotNull(keyPairLoaded);
		Assertions.assertArrayEquals(keyPair.getPublic().getEncoded(), keyPairLoaded.getPublic().getEncoded());
		Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(), keyPairLoaded.getPrivate().getEncoded());
				
		key = keyPair.getPublic();
		Assertions.assertEquals("RSA", key.getAlgorithm());
		encoded = key.getEncoded();
		Assertions.assertNotNull(encoded);
		
		key = keyPair.getPrivate();
		Assertions.assertEquals("RSA", key.getAlgorithm());
		encoded = key.getEncoded();
		Assertions.assertNotNull(encoded);
    }
}
