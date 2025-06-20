<?php

namespace CodersFree\LaravelGreenter\Services;

use CodersFree\LaravelGreenter\Exceptions\GreenterException;
use Greenter\XMLSecLibs\Sunat\SignedXml;

class SignatureService
{
    /**
     * Configurar los métodos de firma para SHA256
     */
    public static function configureSha256Signature(SignedXml $signer): void
    {
        $digestMethod = config('greenter.signature.digest_method', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $signatureMethod = config('greenter.signature.signature_method', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        
        $signer->setDigestMethod($digestMethod);
        $signer->setSignatureMethod($signatureMethod);
    }

    /**
     * Crear un firmador configurado con SHA256
     */
    public static function createSigner(string $certificate): SignedXml
    {
        if (!file_exists($certificate)) {
            throw new GreenterException("Certificate file not found: $certificate");
        }

        $signer = new SignedXml();
        $signer->setCertificate(file_get_contents($certificate));
        
        self::configureSha256Signature($signer);
        
        return $signer;
    }

    /**
     * Verificar si el certificado es compatible con SHA256
     */
    public static function verifyCertificateCompatibility(string $certificatePath): bool
    {
        if (!file_exists($certificatePath)) {
            return false;
        }

        $certificate = file_get_contents($certificatePath);
        $certData = openssl_x509_parse($certificate);
        
        if (!$certData) {
            return false;
        }

        // Verificar que el certificado tenga al menos 2048 bits para SHA256
        $publicKey = openssl_pkey_get_public($certificate);
        if (!$publicKey) {
            return false;
        }

        $keyDetails = openssl_pkey_get_details($publicKey);
        $keySize = $keyDetails['bits'] ?? 0;

        return $keySize >= 2048;
    }
}