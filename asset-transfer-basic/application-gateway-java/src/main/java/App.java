/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.CommitStatusException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.EndorseException;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.Hash;
import org.hyperledger.fabric.client.SubmitException;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;




import java.util.Scanner;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.jpbc.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import java.math.BigInteger;
import java.util.List;
import java.security.SecureRandom;






import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public final class App {
	private static final String MSP_ID = System.getenv().getOrDefault("MSP_ID", "Org1MSP");
	private static final String CHANNEL_NAME = System.getenv().getOrDefault("CHANNEL_NAME", "mychannel");
	private static final String CHAINCODE_NAME = System.getenv().getOrDefault("CHAINCODE_NAME", "basic");

	// Path to crypto materials.
	private static final Path CRYPTO_PATH = Paths.get("../../test-network/organizations/peerOrganizations/org1.example.com");
	// Path to user certificate.
	private static final Path CERT_DIR_PATH = CRYPTO_PATH.resolve(Paths.get("users/User1@org1.example.com/msp/signcerts"));
	// Path to user private key directory.
	private static final Path KEY_DIR_PATH = CRYPTO_PATH.resolve(Paths.get("users/User1@org1.example.com/msp/keystore"));
	// Path to peer tls certificate.
	private static final Path TLS_CERT_PATH = CRYPTO_PATH.resolve(Paths.get("peers/peer0.org1.example.com/tls/ca.crt"));

	// Gateway peer end point.
	private static final String PEER_ENDPOINT = "localhost:7051";
	private static final String OVERRIDE_AUTH = "peer0.org1.example.com";

	private final Contract contract;
	
	private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
	
	public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); 
		
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
		
        return Base64.getEncoder().encodeToString(encryptedBytes); 
    }
	
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
		
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
		
        return new String(decryptedBytes, "UTF-8");
    }
	
	
	public static void main(final String[] args) throws Exception {
		// The gRPC client connection should be shared by all Gateway connections to
		// this endpoint.
		var channel = newGrpcConnection();

		var builder = Gateway.newInstance()
                .identity(newIdentity())
                .signer(newSigner())
                .hash(Hash.SHA256)
                .connection(channel)
				// Default timeouts for different gRPC calls
				.evaluateOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.endorseOptions(options -> options.withDeadlineAfter(15, TimeUnit.SECONDS))
				.submitOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.commitStatusOptions(options -> options.withDeadlineAfter(1, TimeUnit.MINUTES));

		try (var gateway = builder.connect()) {
			new App(gateway).run();
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	private static ManagedChannel newGrpcConnection() throws IOException {
		var credentials = TlsChannelCredentials.newBuilder()
				.trustManager(TLS_CERT_PATH.toFile())
				.build();
		return Grpc.newChannelBuilder(PEER_ENDPOINT, credentials)
				.overrideAuthority(OVERRIDE_AUTH)
				.build();
	}

	private static Identity newIdentity() throws IOException, CertificateException {
		try (var certReader = Files.newBufferedReader(getFirstFilePath(CERT_DIR_PATH))) {
			var certificate = Identities.readX509Certificate(certReader);
			return new X509Identity(MSP_ID, certificate);
		}
	}

	private static Signer newSigner() throws IOException, InvalidKeyException {
		try (var keyReader = Files.newBufferedReader(getFirstFilePath(KEY_DIR_PATH))) {
			var privateKey = Identities.readPrivateKey(keyReader);
			return Signers.newPrivateKeySigner(privateKey);
		}
	}

	private static Path getFirstFilePath(Path dirPath) throws IOException {
		try (var keyFiles = Files.list(dirPath)) {
			return keyFiles.findFirst().orElseThrow();
		}
	}

	public App(final Gateway gateway) {
		// Get a network instance representing the channel where the smart contract is
		// deployed.
		var network = gateway.getNetwork(CHANNEL_NAME);

		// Get the smart contract from the network.
		contract = network.getContract(CHAINCODE_NAME);
	}

	public void run() throws GatewayException, CommitException, Exception {
		// Initialize a set of asset data on the ledger using the chaincode 'InitLedger' function.
		//initLedger();

		createOffer();
		// Return all the current assets on the ledger.
		GetAllOffer();
		
		
		
		// Create a new asset on the ledger.
		/*createAsset();

		// Update an existing asset asynchronously.
		transferAssetAsync();

		// Get the asset details by assetID.
		readAssetById();

		// Update an asset which does not exist.
		updateNonExistentAsset();*/
	}

	/**
	 * This type of transaction would typically only be run once by an application
	 * the first time it was started after its initial deployment. A new version of
	 * the chaincode deployed later would likely not need to run an "init" function.
	 */
	private void initLedger() throws EndorseException, SubmitException, CommitStatusException, CommitException {
		System.out.println("\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger");

		contract.submitTransaction("InitLedger");

		System.out.println("*** Transaction committed successfully");
	}

	/**
	 * Evaluate a transaction to query ledger state.
	 */
	private void GetAllOffer() throws GatewayException {
		System.out.println("\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger");

		var result = contract.evaluateTransaction("GetAllOffer");

		System.out.println("*** Result: " + prettyJson(result));
	}
	
	private void createOffer() throws EndorseException, SubmitException, CommitStatusException, CommitException {
		System.out.println("\n--> Submit Transaction: Offer registration");
		
		SecureRandom rand;
		try {
			byte[] seedBytes = "seed-1234".getBytes(StandardCharsets.UTF_8);
			
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(seedBytes);
		
		
		
			// INIT
			int rBits = 160;
			int qBits = 512;
			BigInteger genVal = new BigInteger("123456789012345678901234567890123456");
			// Osztályszinten / Példányváltozók 
			TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits, false);
			PairingParameters params = pairingGenerator.generate();
			Pairing pairing=PairingFactory.getPairing(params, rand);
			final Element generator = pairing.getG1().newRandomElement().getImmutable();
			Element P = generator.mul(BigInteger.valueOf(1));
			
			BigInteger p = params.getBigInteger("q");
			
			
			System.out.println(params);
			
			// SHAMIR SECRET  SHARING
			
			BigInteger a = (new BigInteger(256, rand)).mod(p);
			BigInteger b = (new BigInteger(256, rand)).mod(p);
			
			BigInteger x0 = (new BigInteger(256, rand)).mod(p);
			BigInteger x1 = (new BigInteger(256, rand)).mod(p);
			
			BigInteger y0 = (a.add(b.multiply(x0))).mod(p);
			BigInteger y1 = (a.add(b.multiply(x1))).mod(p);
			
			BigInteger l0 = (x0.multiply(
				x0.subtract(x1).modInverse(p)
			)).mod(p);
			
			BigInteger l1 = (x1.multiply(
				x1.subtract(x0).modInverse(p)
			)).mod(p);
			
			// COMMON SECRET KEY
			
			BigInteger s0 = y0.multiply(l0).mod(p);
			BigInteger s1 = y1.multiply(l1).mod(p);
			
			
			Element s0P = generator.mul(s0);
			Element l0P = generator.mul(l0);
			
			Element s1P = generator.mul(s1);
			Element l1P = generator.mul(l1);
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			
			long start_time = System.currentTimeMillis(); // tic
			BigInteger x = (new BigInteger(256, rand)).mod(p);
			Element xP = generator.mul(x); // titkosítok
			
			BigInteger a_mask = (new BigInteger(256, rand)).mod(p);
			BigInteger k_i = a_mask;
			
			Element a_maskP = generator.mul(a_mask); // mask
			Element mxP = xP.add(a_maskP); // maskolt
			
			String originalText = "Let me make you an offer: 100 monitors for just 100 dollars.";
			
			///
			byte[] keyBytes = xP.toBytes();
			byte[] aesKey = new byte[32]; 
			int start = Math.max(0, keyBytes.length - aesKey.length);
			System.arraycopy(keyBytes, start, aesKey, Math.max(0, aesKey.length - keyBytes.length), Math.min(keyBytes.length, aesKey.length));

			// Létrehozzuk az AES kulcsot
			SecretKey simkey = new SecretKeySpec(aesKey, "AES");
			
			
			// Titkosítunk
			String ENCm = null;
			try {
				ENCm = encrypt(originalText, simkey);
			} catch (Exception e) {
				e.printStackTrace();
				
			}

			//String ENCm = encrypt(originalText, simkey);
			System.out.println("Titkosított szöveg: " + ENCm);
			//////
			
			List<BigInteger> bigInts = new ArrayList<>();
			
			List<BigInteger> hash_list = new ArrayList<>();
			
			String Mi =ENCm;
			SecretKey simkeyNested = null;
			for(int i=0;i<10;i++){
				
				BigInteger ki = (new BigInteger(256, rand)).mod(p);
				BigInteger xi = (new BigInteger(256, rand)).mod(p);
				Element xiP = generator.mul(xi);
				Element kiP = generator.mul(ki);
				Element kiliP = null;
				
				String Mi_tmp = ki+"||"+(9-i)+"||"+Base64.getEncoder().encodeToString(xiP.toBytes())+"||";
				
				
				
				
				
				if(i%2 == 0){
					kiliP = xiP.mul(l0);
				}else{
					kiliP = xiP.mul(l1);
				}
				//"||" + ENCm
				
				
				
				byte[] keyBytesNested = kiliP.toBytes();
				byte[] aeskeyNested = new byte[32]; 
				int start_nesed = Math.max(0, keyBytesNested.length - aeskeyNested.length);
				System.arraycopy(keyBytesNested, start_nesed, aeskeyNested, Math.max(0, aeskeyNested.length - keyBytesNested.length), Math.min(keyBytesNested.length, aeskeyNested.length));
				
				
				simkeyNested = new SecretKeySpec(aesKey, "AES");
			
			
				// Titkosítunk
				
				try {
					Mi = encrypt(Mi, simkeyNested);
				} catch (Exception e) {
					e.printStackTrace();
					
				}
				
				
				
				byte[] HM_act = Mi.getBytes(); 
				hash_list.add(new BigInteger(1,digest.digest(HM_act)).mod(p));
				
				Mi = Mi_tmp+Mi;
				
				k_i = k_i.multiply(ki);			
				bigInts.add(ki.modInverse(p));
			}
			long end_time = System.currentTimeMillis(); // tac

			long elapsedMs = end_time - start_time;
			System.out.println("Nested enc: " + elapsedMs + " ms");
			
			start_time = System.currentTimeMillis(); // tic
			
			contract.submitTransaction("RegisterCustomOffer",
				"Teszt TLE", 
				Mi, 
				"0", 
				"51110", 
				"6000",
				""+l0P,
				""+l1P
			
			);
			end_time = System.currentTimeMillis();
			elapsedMs = end_time - start_time;
			System.out.println("send to chain the offer: " + elapsedMs + " ms");
			
			
			start_time = System.currentTimeMillis(); // tic
			
			contract.submitTransaction("Shamir");
			end_time = System.currentTimeMillis();
			elapsedMs = end_time - start_time;
			System.out.println("Shamir: " + elapsedMs + " ms");
			
			start_time = System.currentTimeMillis(); // tic
			
			contract.submitTransaction("Chcalc");
			end_time = System.currentTimeMillis();
			elapsedMs = end_time - start_time;
			System.out.println("Chcalc: " + elapsedMs + " ms");
			
			start_time = System.currentTimeMillis(); // tic
			
			contract.submitTransaction("ColChcalc");
			end_time = System.currentTimeMillis();
			elapsedMs = end_time - start_time;
			System.out.println("ColChcalc: " + elapsedMs + " ms");
			
			
			System.out.println("*** Transaction committed successfully");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1PRNG algoritmus nem elérhető", e);
		}
	}

	private String prettyJson(final byte[] json) {
		return prettyJson(new String(json, StandardCharsets.UTF_8));
	}

	private String prettyJson(final String json) {
		var parsedJson = JsonParser.parseString(json);
		return gson.toJson(parsedJson);
	}

	
	/*

	
	private void transferAssetAsync() throws EndorseException, SubmitException, CommitStatusException {
		System.out.println("\n--> Async Submit Transaction: TransferAsset, updates existing asset owner");

		var commit = contract.newProposal("TransferAsset")
				.addArguments(assetId, "Saptha")
				.build()
				.endorse()
				.submitAsync();

		var result = commit.getResult();
		var oldOwner = new String(result, StandardCharsets.UTF_8);

		System.out.println("*** Successfully submitted transaction to transfer ownership from " + oldOwner + " to Saptha");
		System.out.println("*** Waiting for transaction commit");

		var status = commit.getStatus();
		if (!status.isSuccessful()) {
			throw new RuntimeException("Transaction " + status.getTransactionId() +
					" failed to commit with status code " + status.getCode());
		}

		System.out.println("*** Transaction committed successfully");
	}

	private void readAssetById() throws GatewayException {
		System.out.println("\n--> Evaluate Transaction: ReadAsset, function returns asset attributes");

		var evaluateResult = contract.evaluateTransaction("ReadAsset", assetId);

		System.out.println("*** Result:" + prettyJson(evaluateResult));
	}

	
	private void updateNonExistentAsset() {
		try {
			System.out.println("\n--> Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error");

			contract.submitTransaction("UpdateAsset", "asset70", "blue", "5", "Tomoko", "300");

			System.out.println("******** FAILED to return an error");
		} catch (EndorseException | SubmitException | CommitStatusException e) {
			System.out.println("*** Successfully caught the error:");
			e.printStackTrace(System.out);
			System.out.println("Transaction ID: " + e.getTransactionId());
		} catch (CommitException e) {
			System.out.println("*** Successfully caught the error:");
			e.printStackTrace(System.out);
			System.out.println("Transaction ID: " + e.getTransactionId());
			System.out.println("Status code: " + e.getCode());
		}
	}*/
}
