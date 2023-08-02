package rg.sid.security;

import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenerator {

        public static byte[] generateKey(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        Base64.getEncoder().encodeToString(keyBytes);
        return  keyBytes;
    }
    }

