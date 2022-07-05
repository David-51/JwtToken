<?php

namespace Assets;

class JWT
{
    private static array $payload;
        
    /**
     * This method generate a JWT token     
     * @param array $payload the payload
     * @param string|bool $exp expiration time in seconds or false if not expiration time is set.
     * 
     * @return string JWT Token
     */
    public static function generate(array $payload, string|bool $exp) :string
    {
        
        // Add expiration to payload 
        if(!$exp){
            $now = new \DateTime();
            $expiration = $now->getTimestamp() + $exp;
            $payload['iat'] = $now->getTimestamp();
            $payload['exp'] = $expiration;
        }

        // set the JWT header
        $header = ['alg' => 'sha256', 'typ' => 'JWT'];

        // Encode Base64
        $base64Header = base64_encode(json_encode($header));
        $base64Payload = base64_encode(json_encode($payload));

        $base64Header = self::cleanToken($base64Header);
        $base64Payload = self::cleanToken($base64Payload);

        $secret = base64_encode($_ENV['JWT_SECRET']);

        $signature = hash_hmac('sha256', $base64Header . '.' . $base64Payload, $secret, true);

        $base64Signature = base64_encode($signature);
        $base64Signature = self::cleanToken($base64Signature);

        $signature = self::cleanToken($base64Signature);

        return $base64Header . '.' . $base64Payload . '.' . $base64Signature;
    }
    
    /**
     * Clean token from invalid JWT chars
     * @param string $token Token to clean ...
     * @return string $token JWT Token
     */
    private static function cleanToken(string $token) :string
    {
        $token = str_replace(['+', '/', '='], ['-', '_', ''], $token);
        return $token;
    }
    /**
     * This method check if a token is a valid token
     * @param string $token Token to check     
     * @param string $exp expiration time in seconds
     * @return true||false, true if the token is valid
     */
    private static function checkToken(string $token) :bool
    {        
        $payload = self::getPayload($token);
        
        $check_token = self::generate($payload, false);

        return $token === $check_token;
    }
    /**
     * Get the Token's Header
     * This methods is not use because in this first version the the header can't be modified
     * @param string $token JWT Token
     * @return array header
     */
    private static function getHeader(string $token) :array
    {
        // explode token
        $array = explode('.', $token);

        // decode header
        $header = json_decode(base64_decode($array[0], true));
        return (array) $header;
    }

    /**
     * Get the Token's Payload
     * @param string $token JWT Token
     * @return array JWT_Payload || error message
     */
    private static function getPayload(string $token) :array
    {
        // explode token
        $array = explode('.', $token);
        if(!isset($array[0], $array[1], $array[2])){
            return ['error' => "Invalid Token format"];
        }
        // decode header
        $payload = json_decode(base64_decode($array[1], true));
        return (array) $payload;
    }

    /**
     * @param string $token JWT token to test
     * @return bool, true if expired and false if not
     */
    private static function isExpired(string $token) :bool
    {
        $payload = self::getPayload($token);
        $now = new \DateTime();
        return $payload['exp'] < $now->getTimestamp();
    }
    /**
     * This method return a token if a token is received
     * @return string $token||false, return token if a token is received otherwise false
     */
    private static function tokenIsReceived() :string|bool{
        if(isset($_SERVER['Authorization'])){
            return trim($_SERVER['Authorization']);
        }elseif(isset($_SERVER['HTTP_AUTHORIZATION'])){
            return trim($_SERVER['HTTP_AUTHORIZATION']);
        }elseif(function_exists('apache_request_headers')){
            $requestHeaders = apache_request_headers();
            if(isset($requestHeaders['Authorization'])){
                return trim($requestHeaders['Authorization']);
            }
        }
        return false;     
    }
    /**
     * This method test if a JWT is a Bearer Token
     * @param string $token JWT Token to test
     * @return string||array token if token is Bearer
     */
    private static function isBearerToken(string $token) :array|string
    {        
        if(!isset($token) || !preg_match('/Bearer\s(\S+)/', $token, $matches)){
            http_response_code(400);
            return ['error' => 'Token not found'];            
        }else{
            $token = str_replace('Bearer ', '', $token);
            return $token;
        }
    }
    /**
     * This method check if the token is valid and if it is valid return the payload
     * @return array jwt_payload if the token is received and bearer whereas a json error message
     */
    public static function getTokenPayload() :array
    {
        if(isset(self::$payload)){
            return self::$payload;
        }
        $token = self::tokenIsReceived();
        if(!$token){
            http_response_code(403);
            return ['error' => 'Token not found'];
        }                
        $token = self::isBearerToken($token);
        
        $payload = self::getPayload($token);

        if(isset($payload['error'])){
            return $payload;
        }

        if(!self::checkToken($token)){
            http_response_code(403);
            return ['error' => 'invalid Token'];
        }
        if(self::isExpired($token)){
            http_response_code(403);
            return ['error' => 'Token expired'];
            
        }
        $token_payload = self::getPayload($token);
        if(isset($token_payload['error'])){
            return $token_payload;
        }else{
            self::$payload = $token_payload;
            return self::$payload = $token_payload;
        }        
    }
}