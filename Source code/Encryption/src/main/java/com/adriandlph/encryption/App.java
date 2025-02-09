
package com.adriandlph.encryption;

import com.adriandlph.encryption.algorithms.RSA;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;

/**
 *
 * @author adriandlph
 *
 */
public class App {
	
	public static void main(String[] args) {
		int nArgs = args.length;
		if (nArgs <= 0) System.exit(0);
		
		if (args[0].equals("-rsa")) {
			rsa(nArgs, args);
		}
		
	}
	
	private static void rsa(int nArgs, String[] args) {
		if (nArgs >= 2 && args[1].equals("generateKeys")) {
				Integer keyLenght;
				String keyFileName;
				
				System.out.println("#####################");
				System.out.println("# RSA key generator #");
				System.out.println("#####################");
				
				try {
					System.out.print("Key length: ");
					BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
					try {
						keyLenght = Integer.valueOf(in.readLine());
					} catch (NullPointerException | NumberFormatException ex) {
						keyLenght = null;
					}
					
					if (keyLenght == null) {
						System.err.println("Key lenght not valid.");
						System.exit(1);
					}

					System.out.print("File name: ");
					keyFileName = in.readLine();
					if (keyFileName == null || keyFileName.isBlank()) {
						System.err.println("File name not valid.");
						System.exit(1);
					}
					
					
					
					KeyPair keys = RSA.generateKeyPair(keyLenght);
					RSA.saveKeyPair(keys, keyFileName + ".rsa.pub", keyFileName + ".rsa.priv");
					
				} catch (IOException ex) {
					System.err.println("Error reading the input");
				}
				
				
			}
	}

}
