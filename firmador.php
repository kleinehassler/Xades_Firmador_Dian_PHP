
class Firmador{
  
  const POLITICA_FIRMA = array(
    "name"      => "Política de firma para facturas electrónicas de la República de Colombia",
    "url"       => "https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf",
    "digest"    => "sbcECQ7v+y/m3OcBCJyvmkBhtFs=" // digest en sha1 y base64
  );

  private $signTime         = NULL;
  private $signPolicy       = NULL;
  private $publicKey        = NULL;
  private $privateKey       = NULL;
  private $cerROOT          = NULL;
  private $cerINTERMEDIO    = NULL;
  private $tipoDoc          = '01';

  public function retC14DigestSha1($strcadena)
  {
      $strcadena    = str_replace("\r", "", str_replace("\n", "", $strcadena));
      $d1p          = new DOMDocument('1.0','UTF-8');
      $d1p->loadXML($strcadena);
      $strcadena    = $d1p->C14N();
      return base64_encode(hash('sha256' , $strcadena, true ));
  }

  public function firmar($certificadop12, $clavecertificado, $xmlsinfirma)
  {
      if (!$pfx = file_get_contents($certificadop12))
      {
         echo "Error: No se puede leer el fichero del certificado o no existe en la ruta especificada\n";
         exit;
      }

      if (openssl_pkcs12_read($pfx, $key, $clavecertificado))
      {
          $this->publicKey    = $key["cert"];
          $this->privateKey   = $key["pkey"];
      }
      else
      {
          echo "Error: No se puede leer el almacén de certificados o la clave no es la correcta.\n";
          exit;
      }

      $this->signPolicy         = self::POLITICA_FIRMA;
      $this->signatureID        = "Signature-ddb543c7-ea0c-4b00-95b9-d4bfa2b4e411";
      $this->signatureValue     = "SignatureValue-ddb543c7-ea0c-4b00-95b9-d4bfa2b4e411";
      $this->XadesObjectId      = "XadesObjectId-43208d10-650c-4f42-af80-fc889962c9ac";
      $this->KeyInfoId          = "KeyInfoId-".$this->signatureID;

      $this->Reference0Id       = "Reference-0e79b719-635c-476f-a59e-8ac3ba14365d";
      $this->Reference1Id       = "ReferenceKeyInfo";

      $this->SignedProperties   = "SignedProperties-".$this->signatureID;

      $xml1                     = $xmlsinfirma;
      $xml1                     = $this->insertaFirma($xml1);
      return $xml1;
  }


  public function insertaFirma($xml){
      if (is_null($this->publicKey) || is_null($this->privateKey))
         return $xml;
      $d = new DOMDocument('1.0','UTF-8');
      $d->loadXML($xml);
      $canonizadoreal = $d->C14N();
      $documentDigest = base64_encode(hash('sha256' , $canonizadoreal, true ));

      $xmnls_signeg='xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:clm54217="urn:un:unece:uncefact:codelist:specification:54217:2001" xmlns:clm66411="urn:un:unece:uncefact:codelist:specification:66411:2001" xmlns:clmIANAMIMEMediaType="urn:un:unece:uncefact:codelist:specification:IANAMIMEMediaType:2003" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" xmlns:fe="http://www.dian.gov.co/contratos/facturaelectronica/v1" xmlns:qdt="urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2" xmlns:sts="http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures" xmlns:udt="urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';


      $xmlns_keyinfo='xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:clm54217="urn:un:unece:uncefact:codelist:specification:54217:2001" xmlns:clm66411="urn:un:unece:uncefact:codelist:specification:66411:2001" xmlns:clmIANAMIMEMediaType="urn:un:unece:uncefact:codelist:specification:IANAMIMEMediaType:2003" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" xmlns:fe="http://www.dian.gov.co/contratos/facturaelectronica/v1" xmlns:qdt="urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2" xmlns:sts="http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures" xmlns:udt="urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';
      
      $xmnls_signedprops = 'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:clm54217="urn:un:unece:uncefact:codelist:specification:54217:2001" xmlns:clm66411="urn:un:unece:uncefact:codelist:specification:66411:2001" xmlns:clmIANAMIMEMediaType="urn:un:unece:uncefact:codelist:specification:IANAMIMEMediaType:2003" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" xmlns:fe="http://www.dian.gov.co/contratos/facturaelectronica/v1" xmlns:qdt="urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2" xmlns:sts="http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures" xmlns:udt="urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

      $signTime1 = date('Y-m-d\TH:i:s-05:00');

      $certData   = openssl_x509_parse($this->publicKey);
      $certDigest = base64_encode(openssl_x509_fingerprint($this->publicKey, "sha256", true));

      $certIssuer = array();
      foreach ($certData['issuer'] as $item=>$value)
      {
          $certIssuer[] = $item . '=' . $value;
      }

      $certIssuer = implode(', ', array_reverse($certIssuer));

      $prop = '<xades:SignedProperties Id="' . $this->SignedProperties .  '">' .
      '<xades:SignedSignatureProperties>'.
          '<xades:SigningTime>' .  $signTime1 . '</xades:SigningTime>' .
          '<xades:SigningCertificate>'.
              '<xades:Cert>'.
                  '<xades:CertDigest>' .
                      '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />'.
                      '<ds:DigestValue>' . $certDigest . '</ds:DigestValue>'.
                  '</xades:CertDigest>'.
                  '<xades:IssuerSerial>' .
                      '<ds:X509IssuerName>'   . $certIssuer       . '</ds:X509IssuerName>'.
                      '<ds:X509SerialNumber>' . $certData['serialNumber'] . '</ds:X509SerialNumber>' .
                  '</xades:IssuerSerial>'.
              '</xades:Cert>'.
          '</xades:SigningCertificate>' .
          '<xades:SignaturePolicyIdentifier>'.
              '<xades:SignaturePolicyId>' .
                  '<xades:SigPolicyId>'.
                      '<xades:Identifier>' . $this->signPolicy['url'] .  '</xades:Identifier>'.
                      '<xades:Description>'. $this->signPolicy['name'].  '</xades:Description>'.
                  '</xades:SigPolicyId>'.
                  '<xades:SigPolicyHash>' .
                      '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />'.
                      '<ds:DigestValue>' . $this->signPolicy['digest'] . '</ds:DigestValue>'.
                  '</xades:SigPolicyHash>'.
              '</xades:SignaturePolicyId>' .
          '</xades:SignaturePolicyIdentifier>'.
          '<xades:SignerRole>' .
            '<xades:ClaimedRoles>' .
              '<xades:ClaimedRole>supplier</xades:ClaimedRole>' .
            '</xades:ClaimedRoles>' .
          '</xades:SignerRole>' .
      '</xades:SignedSignatureProperties>'.
      '</xades:SignedProperties>';

      // Prepare key info
      $publicPEM = "";
      openssl_x509_export($this->publicKey, $publicPEM);
      $publicPEM = str_replace("-----BEGIN CERTIFICATE-----", "", $publicPEM);
      $publicPEM = str_replace("-----END CERTIFICATE-----", "", $publicPEM);
      $publicPEM = str_replace("\r", "", str_replace("\n", "", $publicPEM));

      $kInfo = '<ds:KeyInfo Id="'.$this->KeyInfoId.'">' .
                '<ds:X509Data>'  .
                    '<ds:X509Certificate>'  . $publicPEM .'</ds:X509Certificate>' .
                '</ds:X509Data>' .
             '</ds:KeyInfo>';

      $keyinfo_para_hash1 = str_replace('<ds:KeyInfo', '<ds:KeyInfo ' . $xmlns_keyinfo, $kInfo);
      $kInfoDigest = $this->retC14DigestSha1($keyinfo_para_hash1);

      $aconop     = str_replace('<xades:SignedProperties', '<xades:SignedProperties ' . $xmnls_signedprops, $prop);
      $propDigest = $this->retC14DigestSha1($aconop);


      $documentDigest = base64_encode(hash('sha256' , $canonizadoreal, true ));

      // Prepare signed info
      $sInfo = '<ds:SignedInfo>' .
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />' .
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />' .
        '<ds:Reference Id="' . $this->Reference0Id . '" URI="">' .
        '<ds:Transforms>' .
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />' .
        '</ds:Transforms>' .
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' .
        '<ds:DigestValue>' . $documentDigest . '</ds:DigestValue>' .
        '</ds:Reference>' .
        '<ds:Reference Id="'.  $this->Reference1Id . '" URI="#'.$this->KeyInfoId .'">' .
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' .
        '<ds:DigestValue>' . $kInfoDigest . '</ds:DigestValue>' .
        '</ds:Reference>' .
        '<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#' . $this->SignedProperties . '">' .
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' .
        '<ds:DigestValue>' . $propDigest . '</ds:DigestValue>' .
        '</ds:Reference>' .
        '</ds:SignedInfo>';


      $signaturePayload = str_replace('<ds:SignedInfo', '<ds:SignedInfo ' . $xmnls_signeg, $sInfo);

      $d1p = new DOMDocument('1.0','UTF-8');
      $d1p->loadXML($signaturePayload);
      $signaturePayload = $d1p->C14N();

      $signatureResult = "";
      $algo = "SHA256";

      openssl_sign($signaturePayload, $signatureResult, $this->privateKey, $algo);

      $signatureResult = base64_encode($signatureResult);

      $sig = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="' . $this->signatureID . '">'.
        $sInfo .
        '<ds:SignatureValue Id="' . $this->signatureValue . '">' .
        $signatureResult .  '</ds:SignatureValue>'  . $kInfo .
        '<ds:Object Id="'.$this->XadesObjectId .'">'.
        '<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="QualifyingProperties-012b8df6-b93e-4867-9901-83447ffce4bf" Target="#' . $this->signatureID . '">' . $prop .
        '</xades:QualifyingProperties></ds:Object></ds:Signature>';

        $buscar = '<ext:ExtensionContent></ext:ExtensionContent>';
        $remplazar = '<ext:ExtensionContent>'.$sig."</ext:ExtensionContent>";

      $pos = strrpos($xml, $buscar);
      if ($pos !== false)
        $xml = substr_replace($xml, $remplazar, $pos, strlen($buscar));
      return $xml;
    }
}
