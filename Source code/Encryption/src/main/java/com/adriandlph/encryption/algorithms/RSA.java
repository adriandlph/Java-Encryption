package com.adriandlph.encryption.algorithms;

import com.auth0.jwt.algorithms.Algorithm;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *
 * @author adriandlph
 * 
 */
public class RSA {
	public static Algorithm getRSAAlgorithm(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		if (publicKey == null) return null;
		if (privateKey == null) return null;
		
		return Algorithm.RSA256(publicKey, privateKey);
	}
	
	public static Algorithm getRSAAlgorithm(KeyPair keyPair) {
		if (keyPair == null) return null;
		
		return RSA.getRSAAlgorithm((RSAPublicKey)keyPair.getPublic(), (RSAPrivateKey)keyPair.getPrivate());
	}
	
	public static Algorithm getRSAAlgorithm(String publicKeyFile, String privateKeyFile) {
		if (publicKeyFile == null) return null;
		if (privateKeyFile == null) return null;
		
		return RSA.getRSAAlgorithm(RSA.loadKeyPair(publicKeyFile, privateKeyFile));
	}
	
	public static KeyPair generateKeyPair(int keysSize) {
		try {
			// Get RSA keys factory
			KeyPairGenerator keysGenerator = KeyPairGenerator.getInstance("RSA");
			keysGenerator.initialize(keysSize);
			
			// Generate key pair
			return keysGenerator.generateKeyPair();
			
		} catch (NoSuchAlgorithmException ex) {
			return null;
		}
	}
	
	public static boolean saveKeyPair(KeyPair keyPair, String pubKeyFileName, String privKeyFileName) {
		return saveKeyInFile(keyPair.getPublic(), pubKeyFileName)
				&& saveKeyInFile(keyPair.getPrivate(), privKeyFileName);
	}
	
	private static boolean saveKeyInFile(Key key, String fileName) {
		File keyFile = new File(fileName);
		
		// File is a directory
		if (keyFile.exists() && keyFile.isDirectory()) {
			return false;
		}
		
		// Create a new file (delete if exists previous)
		try {
			if (keyFile.exists()) keyFile.delete();
			keyFile.createNewFile();
		} catch (IOException ex) {
			System.err.println(ex.toString());
			return false;
		}
		
		// Write key
		try (FileOutputStream fos = new FileOutputStream(keyFile)) {
			fos.write(key.getEncoded());
		} catch (IOException ex) {
			System.err.println(ex.toString());
			return false;
		}
		
		return true;
	}
	
	public static KeyPair loadKeyPair(String publicKeyFile, String privateKeyFile) {
		// Get RSA keys factory
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException ex) {
			System.err.println(ex.toString());
			return null;
		}
		
		// Validate key files
		File pubKeyFile = new File(publicKeyFile);
		File privKeyFile = new File(privateKeyFile);
		if (!pubKeyFile.exists() || !pubKeyFile.isFile() 
			|| !privKeyFile.exists() || !privKeyFile.isFile()) {
			return null;
		}
		
		// Read keys
		byte[] pubKeyBytes;
		byte[] privKeyBytes;
		try {
			pubKeyBytes = Files.readAllBytes(pubKeyFile.toPath());
			privKeyBytes = Files.readAllBytes(privKeyFile.toPath());
		} catch (IOException ex) {
			System.err.println(ex.toString());
			return null;
		}
		
		// Create key pair
		try {
			EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
			return new KeyPair(keyFactory.generatePublic(pubKeySpec), keyFactory.generatePrivate(privKeySpec));
			
		} catch (InvalidKeySpecException ex) {
			System.err.println(ex.toString());
			return null;
		}
	}
}
