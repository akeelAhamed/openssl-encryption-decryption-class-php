<?php
/**
 * Class to Encrypt And Decrypt data
 *
 * @author Akeel Ahamed
 * @link https://github.com/akeelAhamed
 *
 * @version V2.0
 */
class Secure{
    const METHOD = 'aes-256-ctr';

    /**
     * Encrypts the data
     * 
     * @param string $message - plaintext message
     * @param string $key - encryption key (raw binary expected)
     * @param boolean $encode - set to FALSE to prevent base64-encoded 
     * @return string (raw binary)
     */
    public static function encrypt($message, $key, $encode = true)
    {
        $nonceSize = openssl_cipher_iv_length(self::METHOD);
        $nonce = openssl_random_pseudo_bytes($nonceSize);

        try{
         $ciphertext = @openssl_encrypt(
            $message,
            self::METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $nonce
         );
         $sendEncrypt=$nonce.$ciphertext;
         if(!$ciphertext)throw new Exception('Unable To Encrypt Data');
        }catch(Exception $e){
            $encode=false;
            $sendEncrypt=$e->getMessage();
        }

        // Now let's pack the IV and the ciphertext together
        // Naively, we can just concatenate
        if ($encode) {
            $sendEncrypt=base64_encode($sendEncrypt);
        }
        return $sendEncrypt;
    }

    /**
     * Decrypts the data
     * 
     * @param string $message - ciphertext message
     * @param string $key - encryption key (raw binary expected)
     * @param boolean $encoded - set to FALSE to prevent base64-decode
     * @return string
     */
    public static function decrypt($message, $key, $encoded = true){
        if ($encoded) {
         try{
            $message = base64_decode($message, true);
            if ($message === false) {
                throw new Exception('Unable To Decrypt Data');
            }else{
                $nonceSize = openssl_cipher_iv_length(self::METHOD);
                $nonce = mb_substr($message, 0, $nonceSize, '8bit');
                $ciphertext = mb_substr($message, $nonceSize, null, '8bit');

                $plaintext = @openssl_decrypt(
                    $ciphertext,
                    self::METHOD,
                    $key,
                    OPENSSL_RAW_DATA,
                    $nonce
                );
            }
         }catch(Exception $e){
            $plaintext=$e->getMessage();
         }
        }

        return $plaintext;
    }
}


// USAGE

$data_to_encrypt = 'Hello';

$encrypted = Secure::encrypt($data_to_encrypt);
// OUtput - Encrypted data

$decrypted = Secure::decrypt($encrypted);
// Output - Hello
