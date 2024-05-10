package eccproject;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class SecureChannel implements channel{

	private Cipher cipher;
	private AESKey secretKey;
	
	SecureChannel(){
		this.secretKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		this.cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		this.secretKey.setKey(new byte[] { (byte) 0x62, (byte) 0x75, (byte) 0x69, (byte) 0x74, (byte) 0x72, (byte) 0x75, (byte) 0x6e, (byte) 0x67, (byte) 0x68,
										   (byte) 0x69, (byte) 0x65, (byte) 0x75, (byte) 0x31, (byte) 0x36, (byte) 0x36, (byte) 0x31}, (short) 0);
	}
	
	public short receive(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		return decode(inBuf, inOff, inLen, outBuf,  outOff);
	}
	
	public short send(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		return encode(inBuf, inOff, inLen, outBuf,  outOff);
	}
	
	private short encode(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		cipher.init(secretKey, Cipher.MODE_ENCRYPT);
		if (inLen == (short) 70) {
			Util.arrayFillNonAtomic(inBuf, inLen, (short) 10, (byte) 0x00);
		} else if(inLen == (short) 71) {
			Util.arrayFillNonAtomic(inBuf, inLen, (short) 9, (byte) 0x00);
		} else Util.arrayFillNonAtomic(inBuf, inLen, (short) 8, (byte) 0x00);
		return cipher.doFinal(inBuf, inOff, (short) 80, outBuf, outOff);
	}
	
	private short decode(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		cipher.init(secretKey, Cipher.MODE_DECRYPT);
		short m1 = cipher.update(inBuf, inOff, inLen, outBuf, outOff);
		short m2 = cipher.doFinal(inBuf, (short) (inOff + 16) , (short) (inLen - 16), outBuf, (short) (outOff + 16));
		return (short) (m1 + m2);
	}
}
