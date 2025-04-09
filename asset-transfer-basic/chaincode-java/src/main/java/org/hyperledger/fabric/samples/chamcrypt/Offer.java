/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.samples.assettransfer;


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


import java.util.Objects;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import com.owlike.genson.annotation.JsonProperty;

@DataType()
public class Offer {

    @Property()
    private String ID;

    @Property()
    private String TLE;

    @Property()
    private boolean is_ch;
	
	@Property()
    private BigInteger r;
	
	@Property()
    private BigInteger s;

    @Property()
    private String sender;
	
	@Property()
    private String receiver;
	
	
	
	public Offer() {}

    // Opcionális teljes konstruktor
    public Offer(
		@JsonProperty("ID") String ID, 
		@JsonProperty("TLE") String TLE, 
		@JsonProperty("is_ch") boolean is_ch, 
		@JsonProperty("r") String r, 
		@JsonProperty("s") String s, 
		@JsonProperty("sender") String sender, 
		@JsonProperty("receiver") String receiver
	) {
        this.ID = ID;
        this.TLE = TLE;
        this.is_ch = is_ch;
        this.r = new BigInteger(r);
        this.s = new BigInteger(s);
        this.sender = sender;
        this.receiver = receiver;
    }

    // --- Getterek és Setterek ---

    public String getID() {
        return ID;
    }

    public void setID(String ID) {
        this.ID = ID;
    }

    public String getTLE() {
        return TLE;
    }

    public void setTLE(String TLE) {
        this.TLE = TLE;
    }

    public boolean isIs_ch() {
        return is_ch;
    }

    public void setIs_ch(boolean is_ch) {
        this.is_ch = is_ch;
    }

    public BigInteger getR() {
        return r;
    }

    public void setR(BigInteger r) {
        this.r = r;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getReceiver() {
        return receiver;
    }

    public void setReceiver(String receiver) {
        this.receiver = receiver;
    }
	
	
	
	@Override
	public String toString() {
		return "Offer{" +
				"ID='" + ID + '\'' +
				", TLE='" + TLE + '\'' +
				", is_ch=" + is_ch +
				", r=" + r +
				", s=" + s +
				", sender='" + sender + '\'' +
				", receiver='" + receiver + '\'' +
				'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Offer that = (Offer) o;
		return is_ch == that.is_ch &&
				Objects.equals(ID, that.ID) &&
				Objects.equals(TLE, that.TLE) &&
				Objects.equals(r, that.r) &&
				Objects.equals(s, that.s) &&
				Objects.equals(sender, that.sender) &&
				Objects.equals(receiver, that.receiver);
	}

	@Override
	public int hashCode() {
		return Objects.hash(ID, TLE, is_ch, r, s, sender, receiver);
	}
}
