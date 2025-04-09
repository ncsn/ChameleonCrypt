/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.samples.assettransfer;

import java.util.ArrayList;
import java.util.List;

import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import java.math.BigInteger;
import java.util.List;
import java.security.SecureRandom;


import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contact;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.License;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import com.owlike.genson.Genson;

@Contract(
        name = "basic",
        info = @Info(
                title = "ChameleonCrypt",
                description = "ChameleonCrypt sample example",
                version = "0.0.1",
                license = @License(
                        name = "Apache 2.0 License",
                        url = "http://www.apache.org/licenses/LICENSE-2.0.html")
				)
		)
@Default
public final class ChameleonCrypt implements ContractInterface {
    private final Genson genson = new Genson();
    
    private enum AssetTransferErrors {
        ASSET_NOT_FOUND,
        ASSET_ALREADY_EXISTS
    }

	
	
	@Transaction(intent = Transaction.TYPE.SUBMIT)
    public void InitLedger(final Context ctx) {
		
        registerOffer(ctx, 
			new Offer(
				"Elso cucc", 
				"TLE ELSO TESZT", 
				true, 
				"5", 
				"6",
				"GT",
				"CSABI"
			)
		);
    }
	
	@Transaction(intent = Transaction.TYPE.SUBMIT)
    public void RegisterCustomOffer(final Context ctx,final String ID,final String TLE,final boolean is_ch,final String r, final String s,final String sender,final String receiver) {
		
        registerOffer(ctx, 
			new Offer(
				ID, 
				TLE, 
				is_ch, 
				r, 
				s,
				sender,
				receiver
			)
		);
    }
	@Transaction(intent = Transaction.TYPE.SUBMIT)
    public void Shamir(final Context ctx) {
		
		
		
		SecureRandom rand;
		try {
			byte[] seedBytes = "seed-1234".getBytes(StandardCharsets.UTF_8);
			
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(seedBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1PRNG algoritmus nem elérhető", e);
		}
		
		
		// INIT
		int rBits = 160;
		int qBits = 512;
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		// Osztályszinten / Példányváltozók 
		TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits, false);
		PairingParameters params = pairingGenerator.generate();
		Pairing pairing=PairingFactory.getPairing(params, rand);
		final Element generator = pairing.getG1().newRandomElement().getImmutable();
		Element P = generator.mul(BigInteger.valueOf(1));
		
		BigInteger p = params.getBigInteger("q");
		
		// SHAMIR SECRET  SHARING
		
		BigInteger a = (new BigInteger(256, rand)).mod(p);
		BigInteger b = (new BigInteger(256, rand)).mod(p);
		
		BigInteger x0 = one;//(new BigInteger(256, rand)).mod(p);
		BigInteger x1 = two;//(new BigInteger(256, rand)).mod(p);
		
		BigInteger y0 = (a.add(b.multiply(x0))).mod(p);
		BigInteger y1 = (a.add(b.multiply(x1))).mod(p);
		// x - x1 / x0-x1
		BigInteger l0 = (x1.multiply(
			x1.subtract(x0).modInverse(p)
		)).mod(p);
		
		BigInteger l1 = (x0.multiply(
			x0.subtract(x1).modInverse(p)
		)).mod(p);
		
		
		BigInteger s0 = y0.multiply(l0).mod(p);
		BigInteger s1 = y1.multiply(l1).mod(p);
		
		
		
		
		
		
        registerOffer(ctx, 
			new Offer(
				"Elso cucc", 
				"TLE ELSO TESZT", 
				true, 
				"5", 
				"6",
				"GT",
				"CSABI"
			)
		);
    }
	@Transaction(intent = Transaction.TYPE.SUBMIT)
    public void Chcalc(final Context ctx) {
		
		
		
		SecureRandom rand;
		MessageDigest digest;
		try {
			byte[] seedBytes = "seed-1234".getBytes(StandardCharsets.UTF_8);
			digest = MessageDigest.getInstance("SHA-256");
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(seedBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1PRNG algoritmus nem elérhető", e);
		}
		
		
		// INIT
		int rBits = 160;
		int qBits = 512;
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		// Osztályszinten / Példányváltozók 
		TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits, false);
		PairingParameters params = pairingGenerator.generate();
		Pairing pairing=PairingFactory.getPairing(params, rand);
		final Element generator = pairing.getG1().newRandomElement().getImmutable();
		Element P = generator.mul(BigInteger.valueOf(1));
		
		BigInteger p = params.getBigInteger("q");

		
		// SHAMIR SECRET  SHARING
		
		BigInteger a = (new BigInteger(256, rand)).mod(p);
		BigInteger b = (new BigInteger(256, rand)).mod(p);
		
		BigInteger x0 = one;//(new BigInteger(256, rand)).mod(p);
		BigInteger x1 = two;//(new BigInteger(256, rand)).mod(p);
		
		BigInteger y0 = (a.add(b.multiply(x0))).mod(p);
		BigInteger y1 = (a.add(b.multiply(x1))).mod(p);
		// x - x1 / x0-x1
		BigInteger l0 = (x1.multiply(
			x1.subtract(x0).modInverse(p)
		)).mod(p);
		
		BigInteger l1 = (x0.multiply(
			x0.subtract(x1).modInverse(p)
		)).mod(p);
		
		
		BigInteger s0 = y0.multiply(l0).mod(p);
		BigInteger s1 = y1.multiply(l1).mod(p);
		
		
		Element s0P = generator.mul(s0);
		Element l0P = generator.mul(l0);
		
		Element s1P = generator.mul(s1);
		Element l1P = generator.mul(l1);
		
		Element e0 = pairing.pairing(s0P, P);
		Element e1 = pairing.pairing(s1P, P);
		
		
		BigInteger k = s0.add(s1);
		Element K =pairing.pairing(P, P).pow(k); 
		
		
		
		byte[] input = K.toBytes(); // vagy bármi más adat

        
        byte[] hashBytes = digest.digest(input);
		
		BigInteger C = new BigInteger(1, hashBytes);
        
        String hashHex = C.toString(16);
		Element CP = generator.mul(C);
        
		
		
		
		// CHAMELEON HASH
		
		BigInteger r = (new BigInteger(256, rand)).mod(p);
		Element rP = P.mul(r);
		
		
		byte[] M = "Teszt Elek es Vicc Elek".getBytes(); 
        BigInteger mH = new BigInteger(1,digest.digest(M));
		
		Element CH = P.mul(mH.multiply(r).multiply(C).mod(p));
		
		
		
		
		
		
        registerOffer(ctx, 
			new Offer(
				"Elso cucc", 
				"TLE ELSO TESZT", 
				true, 
				"5", 
				"6",
				"GT",
				"CSABI"
			)
		);
    }
	
	@Transaction(intent = Transaction.TYPE.SUBMIT)
    public void ColChcalc(final Context ctx) {
		
		
		
		SecureRandom rand;
		MessageDigest digest;
		try {
			byte[] seedBytes = "seed-1234".getBytes(StandardCharsets.UTF_8);
			digest = MessageDigest.getInstance("SHA-256");
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(seedBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1PRNG algoritmus nem elérhető", e);
		}
		
		
		// INIT
		int rBits = 160;
		int qBits = 512;
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		// Osztályszinten / Példányváltozók 
		TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits, false);
		PairingParameters params = pairingGenerator.generate();
		Pairing pairing=PairingFactory.getPairing(params, rand);
		final Element generator = pairing.getG1().newRandomElement().getImmutable();
		Element P = generator.mul(BigInteger.valueOf(1));
		
		BigInteger p = params.getBigInteger("q");
		
		

		
		// SHAMIR SECRET  SHARING
		
		BigInteger a = (new BigInteger(256, rand)).mod(p);
		BigInteger b = (new BigInteger(256, rand)).mod(p);
		
		BigInteger x0 = one;//(new BigInteger(256, rand)).mod(p);
		BigInteger x1 = two;//(new BigInteger(256, rand)).mod(p);
		
		BigInteger y0 = (a.add(b.multiply(x0))).mod(p);
		BigInteger y1 = (a.add(b.multiply(x1))).mod(p);
		// x - x1 / x0-x1
		BigInteger l0 = (x1.multiply(
			x1.subtract(x0).modInverse(p)
		)).mod(p);
		
		BigInteger l1 = (x0.multiply(
			x0.subtract(x1).modInverse(p)
		)).mod(p);
		
		
		BigInteger s0 = y0.multiply(l0).mod(p);
		BigInteger s1 = y1.multiply(l1).mod(p);
		
		
		Element s0P = generator.mul(s0);
		Element l0P = generator.mul(l0);
		
		Element s1P = generator.mul(s1);
		Element l1P = generator.mul(l1);
		
		Element e0 = pairing.pairing(s0P, P);
		Element e1 = pairing.pairing(s1P, P);
		
		
		
		BigInteger k = s0.add(s1);
		Element K =pairing.pairing(P, P).pow(k); 
		
		byte[] input = K.toBytes(); // vagy bármi más adat

        
        byte[] hashBytes = digest.digest(input);
		
		BigInteger C = new BigInteger(1, hashBytes);
        
        String hashHex = C.toString(16);
		Element CP = generator.mul(C);
        
		
		// CHAMELEON HASH
		
		BigInteger r = (new BigInteger(256, rand)).mod(p);
		Element rP = P.mul(r);
		
		
		byte[] M = "Teszt Elek es Vicc Elek".getBytes(); 
        BigInteger mH = new BigInteger(1,digest.digest(M));
		
		Element CH = P.mul(mH.multiply(r).multiply(C).mod(p));
		
		byte[] M2 = "Kicsit atirt szoveg...".getBytes(); 
		BigInteger m2H = new BigInteger(1,digest.digest(M2)).mod(p);
		
		BigInteger m2Hi = m2H.modInverse(p);
		
		BigInteger r2 = (mH.multiply(m2Hi).mod(p)).multiply(r).mod(p);
		
		
		
		
		
		
        registerOffer(ctx, 
			new Offer(
				"Elso cucc", 
				"TLE ELSO TESZT", 
				true, 
				"5", 
				"6",
				"GT",
				"CSABI"
			)
		);
    }
	
	
	

    private Offer registerOffer(final Context ctx, final Offer s) {
        String sortedJson = genson.serialize(s);
        ctx.getStub().putStringState(s.getID(), sortedJson);
		
        return s;
    }
	

    
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public Offer ReadOffer(final Context ctx, final String ID) {
        String assetJSON = ctx.getStub().getStringState(ID);

        if (assetJSON == null || assetJSON.isEmpty()) {
            String errorMessage = String.format("Asset %s does not exist", ID);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, AssetTransferErrors.ASSET_NOT_FOUND.toString());
        }

        return genson.deserialize(assetJSON, Offer.class);
    }
	
	@Transaction(intent = Transaction.TYPE.EVALUATE)
    public String GetAllOffer(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        List<Offer> queryResults = new ArrayList<>();

		QueryResultsIterator<KeyValue> results = stub.getStateByRange("", "");

        for (KeyValue result: results) {
            Offer s = genson.deserialize(result.getStringValue(), Offer.class);
            System.out.println(s);
            queryResults.add(s);
        }

        return genson.serialize(queryResults);
    }
}
