import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;

public class ServerMain {
	
	public static byte[] testRSA_encrypt(Key key, String text) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(text.getBytes()); 
        return cipherText;
	}
	// private key로 복호화 하는 함수
	public static byte[] testRSA_decrypt(Key key, byte[] cipherText) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
	}
	// public key로 암호화 하는 함수
	public static Key[] generateRSAKey() throws Exception{
		Key[] key = new Key[2];
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Key publicKey = keyPair.getPublic(); 
        Key privateKey = keyPair.getPrivate(); 
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        
        key[0] = publicKey;
        key[1] = privateKey;
        
        return key;
	}
	// public key와 private key를 생성하는 함수
	
	// byte[] to hex
	public static String byteArrayToHex(byte[] ba) {
		if (ba == null || ba.length == 0) {
	        return null;
	    }
		 
	    StringBuffer sb = new StringBuffer(ba.length * 2);
	    String hexNumber;
	    for (int x = 0; x < ba.length; x++) {
	        hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
		 
	        sb.append(hexNumber.substring(hexNumber.length() - 2));
	    }
	    return sb.toString();
	} 
	
	// hex to byte[]
	public static byte[] hexToByteArray(String hex) {
	    if (hex == null || hex.length() == 0) {
	        return null;
	    }

	    byte[] ba = new byte[hex.length() / 2];
	    for (int i = 0; i < ba.length; i++) {
	        ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
	    }
	    return ba;
	}
	
	public static void main(String[] args) throws Exception{
		
		Key[] server_rsaKey = generateRSAKey();
		Key server_publicKey = server_rsaKey[0];
		Key server_privateKey = server_rsaKey[1];
		// Server public, private key 생성
		
		Scanner scan = new Scanner(System.in);
		int port;
		
		System.out.print("Server Port : 3003\n");
		port = 3003;		
		
        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket = serverSocket.accept();
        
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
		
		Message recv_message = (Message)ois.readObject();
		Key client_publicKey = recv_message.public_key;
		// client에서 client public key를 받음
		
		Message send_message = new Message(recv_message.src_addr, recv_message.src_port,
				socket.getLocalAddress().toString(),port,"data",null,server_publicKey);
    	oos.reset();
    	oos.writeObject(send_message);
		// server public Key를 client에게 전송
    	
        while(true){
        	recv_message = (Message)ois.readObject();
        	//System.out.println("rsa>"+recv_message.msg);// 암호화된 문장 확인
        	System.out.println("client>"+
        			new String(testRSA_decrypt(server_privateKey, hexToByteArray(recv_message.msg)))); // server private key로 복호화
        	
        	System.out.print(">");
			String str = scan.nextLine();
			// 보낼 문장 입력
			
			byte[] cipherText = testRSA_encrypt(client_publicKey,str); // 입력한 문장을 server의 public key로 암호화
			//System.out.println("rsa>"+byteArrayToHex(cipherText));// 암호화된 문장 확인
        	send_message = new Message(recv_message.src_addr, recv_message.src_port,
        			socket.getLocalAddress().toString(),port,"data",byteArrayToHex(cipherText), null);// 암호화된 문장 전송
        	oos.reset();
        	oos.writeObject(send_message);
        }
	}
}
