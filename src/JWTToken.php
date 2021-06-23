<?php

namespace JWTUtils;

use DateTime;

class JWTToken
{

    protected JWTArray $header;
    protected JWTArray $payload;
    protected string $signature;
    protected JWTUtils $utils;

    /**
     * JWTToken __construct
     * 
     * @param array       $header
     * @param array       $payload
     * @param string|null $signature
     * 
     * @return JWTToken
     */
    public function __construct(JWTArray $header, JWTArray $payload, ?string $signature = null)
    {
        $this->header    = $header;
        $this->payload   = $payload;
        $this->signature = $signature ?? JWTSigner::getInstance()->sign($header, $payload);
    }

    /**
     * Get the value of header
     *
     * @return JWTArray
     */
    public function getHeader(): JWTArray
    {
        return $this->header;
    }

    /**
     * Get the value of payload
     *
     * @return JWTArray
     */
    public function getPayload(): JWTArray
    {
        return $this->payload;
    }

    /**
     * Get the value of signature
     *
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * Get the string token
     * 
     * @return string
     */
    public function getToken(): string {
        $header  = $this->getHeader()->encode();
        $payload = $this->getPayload()->encode();
        $signature = $this->getSignature();
        return "$header.$payload.$signature";
    }

    /**
     * Return true if the token is valid
     * => Check iat, exp, nbf values and signature
     * 
     * @return bool
     */
    public function isValid(): bool
    {

        if($this->getPayload()->exist(JWTConstants::PAYLOAD_ISSUED_AT))
        {
            $dateToken = new DateTime();
            $dateToken->setTimestamp((int) $this->getPayload()->get(JWTConstants::PAYLOAD_ISSUED_AT));
            
            if($dateToken > new Datetime())
            {
                return false;
            }
        }
        
        if($this->getPayload()->exist(JWTConstants::PAYLOAD_EXPIRATION_TIME))
        {
            $dateExp = new DateTime();
            $dateExp->setTimestamp((int) $this->getPayload()->get(JWTConstants::PAYLOAD_EXPIRATION_TIME));
            
            if($dateExp < new Datetime())
            {
                return false;
            }
        }

        if($this->getPayload()->exist(JWTConstants::PAYLOAD_NOT_BEFORE))
        {
            $dateBegin = new Datetime();
            $dateBegin->setTimestamp((int) $this->getPayload()->get(JWTConstants::PAYLOAD_NOT_BEFORE));

            if($dateBegin > new Datetime())
            {
                return false;
            }
        }

        return hash_equals($this->getSignature(), JWTSigner::getInstance()->sign($this->getHeader(), $this->getPayload()));
    }

    /**
     * Check if the payload[$key] value and $value are equals
     * 
     * @param string $key
     * @param string $value
     * 
     * @return bool
     */
    public function check(string $key, string $value): bool
    {

        if(!$this->getPayload()->exist($key))
        {
            return false;
        }
        return $this->getPayload()[$key] === $value;
    }

    /**
     * Return true if token is issued by given value
     * 
     * @param string $issuer
     * 
     * @return bool
     */
    public function checkIssuer(string $issuer): bool
    {
        return $this->check(JWTConstants::PAYLOAD_ISSUER, $issuer);
    }

    /**
     * Return true if token is related for given value
     * 
     * @param string $subject
     * 
     * @return bool
     */
    public function checkSubject(string $subject): bool
    {
        return $this->check(JWTConstants::PAYLOAD_SUBJECT, $subject);
    }

    /**
     * Return true if token is permitted for given value
     * 
     * @param string $audience
     * 
     * @return bool
     */
    public function checkAudience(string $audience): bool
    {
        return $this->check(JWTConstants::PAYLOAD_AUDIENCE, $audience);
    }

    /**
     * Return true if token is identified by given value
     * 
     * @param string $jwtID
     * 
     * @return bool
     */
    public function checkJwtID(string $jwtID): bool
    {
        return $this->check(JWTConstants::PAYLOAD_ID, $jwtID);
    }

    /**
     * Check all standard claim values
     * 
     * @param string|null $issuer
     * @param string|null $subject
     * @param string|null $audience
     * @param string|null $jwtID
     * 
     * @return bool
     */
    public function checkAll(?string $issuer = null, ?string $subject = null, ?string $audience = null, ?string $jwtID = null): bool
    {
        return (is_null($issuer)   ? true : $this->checkIssuer($issuer))
            && (is_null($subject)  ? true : $this->checkSubject($subject))
            && (is_null($audience) ? true : $this->checkAudience($audience))
            && (is_null($jwtID)    ? true : $this->checkJwtID($jwtID));
    }

    /**
     * __toString method
     * 
     * @return string
     */
    public function __toString(): string
    {
        return $this->getToken();
    }

}