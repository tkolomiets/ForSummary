unit Crypto;

interface

uses
 Windows,
 System.NetEncoding, System.SysUtils,
 XMLDoc, XMLIntf,
 wcrypt2,  c14n_TLB,
 Classes;

type
  TCrypto = class
  private
    const
     CALG_GR3411 = 32798;
     CALG_GR3410EL = 11811;
     PKCS_7_ASN_ENCODING = 65536;
     CALG_G28147 = 26142;
     CALG_PRO_EXPORT = 26143;
     CALG_DH_EL_EPHEM = $aa25;
     const INFOTECS_PROV_TYPE = 2;
     const PROV_GOST_94_DH = 71;
     const PROV_GOST_2001_DH = 75;
     const PROV_GOST_2012_256 = 80;
     const PROV_GOST_2012_512 = 81;

    class var fCanonicalizer: XmlCanonicalizer;
    class property Canonicalizer: XmlCanonicalizer read fCanonicalizer;

    class function ReverseArray(ASource: TBytes): TBytes;
    class function GetRemotePublicKeyBlob(ACryptoProvider: HCRYPTPROV; ARemoteCertPath: string): TBytes;
    class function GetProviderPublicCertificate(ACryptoProvider: HCRYPTPROV): string;
    class procedure FormatStream(AStream: TStream; AContent: string);
    class procedure SetEncryptedContent(
       ASOAPRequest: IXMLDocument;
       AEncryptedData: TBytes;
       AEncryptedKey: TBytes;
       AProviderCertificate: string);
    class function CreateDecryptedContent(ADecryptedData: TBytes): string;
    class procedure GetResponseKeysBlobs(ASOAPResponse: IXMLDocument; out APublicKeyBlob: TBytes; out ASessionKeyBlob: TBytes);
    class function GetEncryptedResponseDataBlob(ASOAPResponse: IXMLDocument): TBytes;
    class procedure CheckCryptoCall(AResult: Boolean);

    class procedure InitContext(ACryptoPovider: PHCRYPTPROV; ACryptoPoviderType: integer; ACryptoPoviderContainer: PWideChar);
    class procedure ReleaseContext(ACryptoPovider: HCRYPTPROV);
    class function CreateHash(ACryptoProvider: HCRYPTPROV; AData: string): HCRYPTHASH;
    class function GetHashValue(AHash: HCRYPTHASH): TBytes;
    class function CreateSignature(AHash: HCRYPTHASH): TBytes;

    class procedure PrepareSOAPRequest(ASourceSOAP: IXMLDocument; AFormattedSOAP: IXMLDocument);
    class procedure SignSOAPRequest(ACryptoProvider: HCRYPTPROV; ASOAPRequest: IXMLDocument);
    class procedure EncryptSOAPRequest(ACryptoProvider: HCRYPTPROV; ARemoteCertPath: string; ASOAPRequest: IXMLDocument);
    class function CheckFailedResponse(ASOAPResponse: IXMLDocument): boolean;
    class function DecryptSOAPResponse(ACryptoProvider: HCRYPTPROV; ASOAPResponse: IXMLDocument): string;

  public
     class procedure Initialize;
     class procedure Release;
     class procedure FssOnBeforeExecute(const MethodName: string; SOAPRequest: TStream);
     class procedure FssOnAfterExecute(const MethodName: string; SOAPResponse: TStream);
 end;

implementation

uses
  ActiveX, Xml.xmldom, Vcl.Forms;

class procedure TCrypto.CheckCryptoCall(AResult: Boolean);
begin
  if Not AResult then
    RaiseLastOSError;
end;

// ��������� ��������� ������-����������
class procedure TCrypto.InitContext(ACryptoPovider: PHCRYPTPROV;
           ACryptoPoviderType: integer; ACryptoPoviderContainer: PWideChar);
begin
  CheckCryptoCall(CryptAcquireContext(ACryptoPovider, ACryptoPoviderContainer, '', ACryptoPoviderType, 0));
end;

class procedure TCrypto.ReleaseContext(ACryptoPovider: HCRYPTPROV);
begin
  CheckCryptoCall(CryptReleaseContext(ACryptoPovider, 0));
end;

// ���������� ���� ������
class function TCrypto.CreateHash(ACryptoProvider: HCRYPTPROV; AData: string): HCRYPTHASH;
var
  sCanonicalizedData, error: string;
  pCanonicalizedData: PSafeArray;
  aByte: TBytes;
  i, count, max: integer;
  res : HRESULT;
begin
  try
    // ������������ ������ �� ������ COM-������� ����������� (c#)

    pCanonicalizedData := Canonicalizer.TransformXmlToC14n(AData);
    Count := SafeArrayGetDim(pCanonicalizedData);
    SafeArrayGetUBound(pCanonicalizedData, count, max);

    for i := 0 to max do
    begin
      res := SafeArrayGetElement(pCanonicalizedData, i, sCanonicalizedData);

      case res of
        DISP_E_BADINDEX: error := 'The specified index was invalid';
        E_INVALIDARG:    error := 'One of the arguments is invalid';
        E_OUTOFMEMORY:   error := 'Memory could not be allocated for the element';
      end;

      if Not error.IsEmpty then
        raise Exception.CreateFmt('����������� ������ ����: %s.', [error]);
    end;

    i := sCanonicalizedData.LastIndexOf('>');
    sCanonicalizedData := sCanonicalizedData.Substring(0, i + 1);
    aByte := TEncoding.Utf8.GetBytes(sCanonicalizedData);

    // ���������� ���� �� ������ ���������������� ������

    CheckCryptoCall(CryptCreateHash(ACryptoProvider, CALG_GR3411, 0, 0, @Result));
    CheckCryptoCall(CryptHashData(Result, PByte(aByte), Length(aByte), 0));
  finally
    SetLength(aByte, 0);
    SafeArrayDestroy(pCanonicalizedData)
  end;
end;

// ���������� ������ �� ����.
// ��������, ��� ��������� ��� ����� � XML-���� ���������.
class function TCrypto.GetHashValue(AHash: HCRYPTHASH): TBytes;
var
  pbHash: PBYTE;
  hashSize, dwSize: DWORD;
begin
  // ���������� ����������� ��������� �� ����� �������� ����
  dwSize := sizeof(DWORD);
  CheckCryptoCall(CryptGetHashParam(AHash, HP_HASHSIZE, @hashSize, @dwSize, 0));

  try
    // ��������� ������ ��� ��������� �� ����� �������� ����
    GetMem(pbHash, hashSize);
    // ��������� �������� ���� � ��� �������
    CheckCryptoCall(CryptGetHashParam(AHash, HP_HASHVAL, pbHash, @hashSize, 0));

    // ��������� ������ ��� �������� ����
    SetLength(Result, hashSize);
    Move(pbHash^, Result[0], hashSize);
  finally
    if Assigned(pbHash) then
      FreeMem(pbHash);
  end;
end;

// ��������� �� �� ����������� ������� ���� ������
class function TCrypto.CreateSignature(AHash: HCRYPTHASH): TBytes;
var
  hashSize: DWORD;
  pbHash: PBYTE;
  aByte: TBytes;
begin
  // ���������� ������� �� ���� ������
  hashSize := 0;
  CheckCryptoCall(CryptSignHash(AHash, AT_KEYEXCHANGE, nil, 0, nil, @hashSize));

  if hashSize > 0 then
    try
      GetMem(pbHash, hashSize);
      // ��������� �� ���� ������
      CheckCryptoCall(CryptSignHash(AHash, AT_KEYEXCHANGE, nil, 0, pbHash, @hashSize));

      SetLength(aByte, hashSize);
      Move(pbHash^, aByte[0], hashSize);

      // �������������� �������� (�������� ������� ����). �� ����������� ������� ��� ���������
      // ��� ���������� ��������� ������� � ���. ������, ������� � ������� �� ����������������.
      Result := ReverseArray(aByte);
    finally
      if Assigned(pbHash) then
        FreeMem(pbHash);

      SetLength(aByte, 0)
    end;
end;

// ��������� ����������� ��������� ����� �� ���������� ����������������
class function TCrypto.GetProviderPublicCertificate(ACryptoProvider: HCRYPTPROV): string;
var
  hPrivateKey: HCRYPTKEY;
  size: DWORD;
  certData: TBytes;
begin
  Result := '';

  try
    // ��������� ��������� ����� ����������������
    CheckCryptoCall(CryptGetUserKey(ACryptoProvider, AT_KEYEXCHANGE, @hPrivateKey));

    CheckCryptoCall(CryptGetKeyParam(hPrivateKey, KP_CERTIFICATE, nil, @size, 0));
    SetLength(certData, size);
    CheckCryptoCall(CryptGetKeyParam(hPrivateKey, KP_CERTIFICATE, @certData[0], @size, 0));

    Result := TNetEncoding.Base64.EncodeBytesToString(certData);
  finally
    SetLength(certData, 0);

    if hPrivateKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hPrivateKey));
  end;
end;

// �������������� �������� ������� (�������� ������� ����)
class function TCrypto.ReverseArray(ASource: TBytes): TBytes;
var
  len, i: integer;
begin
  len := Length(ASource);
  SetLength(Result,len);

  for i := 0 to len - 1 do
    Result[len - 1 - i] := ASource[i];
end;

class procedure TCrypto.Initialize;
begin
  // c# COM-������� ���������� ������������
  fCanonicalizer := CoXmlCanonicalizer.Create;
end;

class procedure TCrypto.Release;
begin
  fCanonicalizer := nil;
end;

// ��������� BLOB-� ��������� ����� ���������� ������������� ���������
// - ARemoteCertPath - ���� � ����������� ��������� ����� ���������� ������������� ���������
class function TCrypto.GetRemotePublicKeyBlob(ACryptoProvider: HCRYPTPROV; ARemoteCertPath: string): TBytes;
var
  memStream : TMemoryStream;
  certContext: PCCERT_CONTEXT;
  remotePublicKey: HCRYPTKEY;
  size: DWORD;
begin
  try
    memStream := TMemoryStream.Create;
    memStream.LoadFromFile(ARemoteCertPath);

    certContext := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, memStream.Memory, memStream.Size);

    // ������ ���������� �� ��������� ����� ���
    CheckCryptoCall(CryptImportPublicKeyInfoEx(
              ACryptoProvider,
              X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
              @certContext.pCertInfo.SubjectPublicKeyInfo,
              CALG_GR3410EL,
              0,
              nil,
              @remotePublicKey));

    CheckCryptoCall(CryptExportKey(remotePublicKey, 0, PUBLICKEYBLOB, 0, nil, @size));
    SetLength(Result, size);
    CheckCryptoCall(CryptExportKey(remotePublicKey, 0, PUBLICKEYBLOB, 0, @Result[0], @size));
  finally
    memStream.Free;

    if Assigned(certContext) then
      CertFreeCertificateContext(certContext);

    if remotePublicKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(remotePublicKey));
  end;
end;

// ������ ����������� TStream �� �����
class procedure TCrypto.FormatStream(AStream: TStream; AContent: string);
var
  resXmlDoc: IXMLDocument;
begin
  resXMLDoc :=  Xml.XMLDoc.NewXMLDocument;

  try
    resXMLDoc.Options := resXMLDoc.Options - [doNodeAutoIndent];
    resXMLDoc.ParseOptions := resXMLDoc.ParseOptions - [poPreserveWhiteSpace];
    resXMLDoc.LoadFromXML(UTF8String(AContent));
    (TMemoryStream(AStream)).Clear;
    AStream.Position := 0;
    resXMLDoc.SaveToStream(AStream);
  finally
    resXMLDoc := nil;
  end;
end;

// ������������ ��������� EncryptedData �������������� SOAP-���������
// - AEncryptedData ����������� �������������� ������� SOAP-������
// - AEncryptedKey - ASN-��������� GostR3410-KeyTransport ��� ������������ ����������� ����� ����������
//                    �� ������� ���������� �������������� ���������
// - AProviderCertificate - ���������� ��������� �����, �� ������ �������� ���� ����������� ���������,
//                          (�������� ���� ���������� �������������� ���������)
class procedure TCrypto.SetEncryptedContent(
       ASOAPRequest: IXMLDocument;
       AEncryptedData: TBytes;
       AEncryptedKey: TBytes;
       AProviderCertificate: string);
var
  encryptDataDoc: IXMLDocument;
  requestBodyNode, encryptDataNode, encryptCertificateNode,
  encryptCipherDataNode, encryptKeyNode: IXMLNode;
begin
  try
    encryptDataDoc := LoadXMLDocument(ExtractFilePath(Application.ExeName) + 'regiemk_fss_encrypt_body.xml');
    encryptDataNode := encryptDataDoc.DocumentElement;
    requestBodyNode := ASOAPRequest.DocumentElement.ChildNodes[1];

    encryptCertificateNode := encryptDataNode
                             .ChildNodes[1]  // KeyInfo
                             .ChildNodes[0]  // EncryptedKey
                             .ChildNodes[1]  // KeyInfo
                             .ChildNodes[0]  // X509Data
                             .ChildNodes[0]; // X509Certificate

    encryptCipherDataNode := encryptDataNode
                             .ChildNodes[2]  // CipherData
                             .ChildNodes[0]; // CipherValue

    encryptKeyNode := encryptDataNode
                            .ChildNodes[1]  // KeyInfo
                            .ChildNodes[0]  // EncryptedKey
                            .ChildNodes[2]  // CipherData
                            .ChildNodes[0]; // CipherValue

    encryptCipherDataNode.Text := TNetEncoding.Base64.EncodeBytesToString(AEncryptedData);
    encryptKeyNode.Text := TNetEncoding.Base64.EncodeBytesToString(AEncryptedKey);
    encryptCertificateNode.Text := AProviderCertificate;

    requestBodyNode.ChildNodes.Remove(requestBodyNode.ChildNodes[0]);
    requestBodyNode.ChildNodes.Add(encryptDataNode);
  finally
    encryptDataDoc := nil;
  end;
end;

// �������������� �������������� �������� �������� SOAP-�������
// (���������� ����������� �������� � �.�.)
class function TCrypto.CreateDecryptedContent(ADecryptedData: TBytes): string;
begin
  Result := TEncoding.Ansi.GetString(ADecryptedData);
  Result := Result.Remove(Result.IndexOf('</S:Envelope>') + Length('</S:Envelope>'));
end;

class procedure TCrypto.GetResponseKeysBlobs(ASOAPResponse: IXMLDocument;
        out APublicKeyBlob: TBytes;
        out ASessionKeyBlob: TBytes);
var
  transportNode: IXMLNode;
  transport, publicKey, sessionKey,
  sessionSV, sessionMAC: TBytes;
begin
  try
    transportNode := ASOAPResponse.DocumentElement
                     .ChildNodes[1]  // Body
                     .ChildNodes[0]  // EncryptedData
                     .ChildNodes[1]  // KeyInfo
                     .ChildNodes[0]  // EncryptedKey
                     .ChildNodes[2]  // CipherData
                     .ChildNodes[0]; // CipherValue

    transport := TNetEncoding.Base64.DecodeStringToBytes(transportNode.Text);

    publicKey := Copy(transport, 93, 64);
    sessionKey := Copy(transport, 7, 32);
    sessionMAC := Copy(transport, 41, 4);
    sessionSV := Copy(transport, 159, 8);

    APublicKeyBlob :=
      [
       $06,       // bType = PUBLICKEYBLOB
       $20,       // bVersion = 0x20
       $00, $00,
       $23, $2E, $00, $00, // KeyAlg = ALG_SID_GR3410EL
       $4D, $41, $47, $31, //Magic = GR3410_1_MAGIC
       $00, $02, $00, $00, // BitLen = 512
       // bASN1GostR3410_94_PublicKeyParameters
       $30, $12,
       $06, $07 ,
       $2A, $85, $03, $02, $02, $24, $00,
       $06, $07,
       $2A, $85, $03, $02, $02, $1E, $01
      ] + publicKey;


    // ������ SessionKey BLOB �� ����������� ����� � ���������� ����������� �����
    ASessionKeyBlob :=
    [
     $01, // bType = SIMPLEBLOB
     $20, // bVersion = 0x20
     $00,$00 ,
     $1E,$66 ,$00 ,$00, // KeyAlg = CALG_G28147
     $FD,$51 ,$4A ,$37, // Magic = G28147_MAGIC
     $1E,$66 ,$00 ,$00] // EncryptKeyAlgId = CALG_G28147
     + sessionSV + sessionKey + sessionMAC +
    [// ASN.1 Sequence + OID Header
       $30 ,$09 ,$06 ,$07,
     // OID_GOST_R28147_89_CryptoPro_A_ParamSet 1.2.643.2.2.31.1
     $2A ,$85 ,$03 ,$02 ,$02 ,$1F ,$01
    ];
  finally
    SetLength(sessionSV, 0);
    SetLength(sessionMac, 0);
    SetLength(sessionKey, 0);
    SetLength(publicKey, 0);
    SetLength(transport, 0);
  end;


end;

// ��������� �������� �������������� �������� SOAP-��������� �� ���������
// ��������� ������������� SOAP-���������
class function TCrypto.GetEncryptedResponseDataBlob(ASOAPResponse: IXMLDocument): TBytes;
var
  dataNode: IXMLNode;
begin
  dataNode := ASOAPResponse.DocumentElement
                   .ChildNodes[1]  // Body
                   .ChildNodes[0]  // EncryptedData
                   .ChildNodes[2]  // CipherData
                   .ChildNodes[0]; // CipherValue

  Result := TNetEncoding.Base64.DecodeStringToBytes(dataNode.Text);
end;

// ���������� ��������� �������� SOAP-������� � ������� � ����������
// ASourceSOAP - ������� SOAP-������, ��������� ������ ������ ������-������� ���-�������
// AFormattedSOAP - ������ ������������ SOAP-��������, ������� �������������� ���������:
// - ��������� ��������� ��,
// - ����������� ��� ���������� ���������� �������� XML-�����
// - � �.�.
class procedure TCrypto.PrepareSOAPRequest(ASourceSOAP: IXMLDocument; AFormattedSOAP: IXMLDocument);
var
  bodyNode, fssOperationNode, ogrnNode: IXMLNode;
  i: integer;
begin
  // ��������� �� �������� SOAP-������� ���� ������-�������� (��������, ��������� ������ ���)
  fssOperationNode := ASourceSOAP.DocumentElement
                             .ChildNodes[0]  // Body
                             .ChildNodes[0]; // Operation (��������, getNewLNNumRange)

  // ��������� �� ������� ������������ SOAP-��������� ���� SOAP-�������
  bodyNode := AFormattedSOAP.DocumentElement.ChildNodes[1];

  // ������������ ���� ������-�������� ��� ������� ������������ SOAP-���������
  bodyNode.ChildNodes.Add(fssOperationNode);

  // �������� ���� �����������
  for i := 0 to fssOperationNode.ChildNodes.Count - 1 do
   if AnsiLowerCase(fssOperationNode.ChildNodes[i].LocalName) = 'ogrn' then
     ogrnNode := fssOperationNode.ChildNodes[i];

  // ������������� ����������� ���� �� ����� SOAP-���������
  AFormattedSOAP.LoadFromXML(AFormattedSOAP.DocumentElement.XML.Replace('OGRNNUMBER', ogrnNode.Text));
end;

// ������� SOAP-�������
class procedure TCrypto.SignSOAPRequest(ACryptoProvider: HCRYPTPROV; ASOAPRequest: IXMLDocument);
var
  headerNode, bodyNode, securityNode,
  signatureNode, signValueNode, signInfoNode,
  referenceNode, digestValueNode, certificateNode: IXMLNode;
  hash: HCRYPTHASH;
  hashValue: TBytes;
begin
  // ��������� ���������� XML-�����
  headerNode := ASOAPRequest.DocumentElement.ChildNodes[0];
  bodyNode := ASOAPRequest.DocumentElement.ChildNodes[1];
  securityNode := headerNode.ChildNodes[0];
  certificateNode := securityNode.ChildNodes[1];
  signatureNode := securityNode.ChildNodes[0];
  signInfoNode :=  signatureNode.ChildNodes[0];
  signValueNode := signatureNode.ChildNodes[1];
  referenceNode := signInfoNode.ChildNodes[2];
  digestValueNode :=  referenceNode.ChildNodes[2];

  // ������������ ��������� ���� SOAP-������� (��������, getNewLNNumRange)
  try
    // ���������� ���������
    hash := CreateHash(ACryptoProvider, bodyNode.XML);
    hashValue := GetHashValue(hash);

    // ��������� BASE64 �������� ��������� � ���� digestValue
    digestValueNode.Text := TNetEncoding.Base64.EncodeBytesToString(hashValue);
  finally
    if hash <> 0 then
    begin
      CheckCryptoCall(CryptDestroyHash(hash));
      SetLength(hashValue, 0);
    end;
  end;

  // ��������� �� �� ����������� �������� ���� SOAP-�������.
  try
    // ���������� ��
    hash := CreateHash(ACryptoProvider, signInfoNode.Xml);
    hashValue := CreateSignature(hash);

    // ��������� BASE64 �������� �� � ���� signValue
    signValueNode.Text := TNetEncoding.Base64.EncodeBytesToString(hashValue);
  finally
    if hash <> 0 then
    begin
      CheckCryptoCall(CryptDestroyHash(hash));
      SetLength(hashValue, 0);
    end;
  end;

  // �������� ����������� ��������� �����, �� ������ �������� ������������� ��.
  certificateNode.Text := GetProviderPublicCertificate(ACryptoProvider);
end;

class function TCrypto.CheckFailedResponse(ASOAPResponse: IXMLDocument): boolean;
var
  node : IXMLNode;
begin
  Result := False;

  // ��������� ����������� XML-�����
  if ASOAPResponse.DocumentElement.ChildNodes.Count = 1 then
  begin
    node := ASOAPResponse.DocumentElement.ChildNodes[0];

    Result := (node.ChildNodes.Count = 1) And
       (node.ChildNodes[0].LocalName = 'Fault');

  end;
end;

// ���������� SOAP-�������
class procedure TCrypto.EncryptSOAPRequest(ACryptoProvider: HCRYPTPROV; ARemoteCertPath: string; ASOAPRequest: IXMLDocument);
var
  hEphemeralKey, hAgreeKey, hSessionKey: HCRYPTKEY;

  size, keyParam,
  sourceDataLen, encryptDataLen: DWORD;

  remotePublicKeyBlob, providerPublicKeyBlob,
  sessionKeyBlob, transportBlob,
  sessionSV, sessionKey, sessionMAC,
  publicKey, initVector,
  encryptedData: TBytes;
begin
  try
    // ������������ ���������� ����� � �������� ���������� ��������� �����
    // ����������� �������������� ���������.
    // � ��������, �������� ����� � �� ������� ��������� �������� ����� (CryptGetUserKey).
    CheckCryptoCall(CryptGenKey(ACryptoProvider, CALG_DH_EL_EPHEM, CRYPT_EXPORTABLE, @hEphemeralKey));

    // ������� ��������� ����� � BLOB �� ���������� ���������.
    CheckCryptoCall(CryptExportKey(hEphemeralKey, 0, PUBLICKEYBLOB, 0, nil, @size));
    SetLength(providerPublicKeyBlob, size);
    CheckCryptoCall(CryptExportKey(hEphemeralKey, 0, PUBLICKEYBLOB, 0, @providerPublicKeyBlob[0], @size));

    // ��������� �� BLOB-� �������� ��������� ����� (��������� BLOB-� ��. � GetResponseKeysBlobs),
    // ������� ����� ������ � GostR3410-KeyTransport
    publicKey := Copy(providerPublicKeyBlob, Length(providerPublicKeyBlob) - 64, 64);

    // ��������� BLOB ��������� ����� ���������� ���������� �������������� ��������� (���).
    // ARemoteCertPath - ���� � ����������� ��������� ����� ���������� ���������� �������������� ���������,
    // �������, �����, ����������� � �������� �������, �� ����� ����������.
    remotePublicKeyBlob := GetRemotePublicKeyBlob(ACryptoProvider, ARemoteCertPath);

    // ��������� ����� ������������ �������� ��������� ����� ���������� �������������� ��������� (���)
    // �� ��������� �������� ����� ����������� �������������� ���������.
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remotePublicKeyBlob[0], Length(remotePublicKeyBlob),
                                       hEphemeralKey, 0, @hAgreeKey));

    // ��������� PRO_EXPORT ��������� ����� ������������
    keyParam := CALG_PRO_EXPORT;
    CheckCryptoCall(CryptSetKeyParam(hAgreeKey, KP_ALGID, @keyParam, 0));

    // �������� ���������� ����������� �����, ������� ����� ����������� ���������.
    CheckCryptoCall(CryptGenKey(ACryptoProvider, CALG_G28147, CRYPT_EXPORTABLE, @hSessionKey));

    // ������� ����������� ����� � BLOB
    CheckCryptoCall(CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, nil, @size));
    SetLength(sessionKeyBlob, size);
    CheckCryptoCall(CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, @sessionKeyBlob[0], @size));

    // ��������� �� BLOB-� �������� ��������� UKM, ����������� �����, MAC. ��������� BLOB-� ��. � GetResponseKeysBlobs.
    sessionSV  := Copy(sessionKeyBlob, 16, 8);
    sessionKey := Copy(sessionKeyBlob, 24, 32);
    sessionMAC := Copy(sessionKeyBlob, 56, 4);

    // ������������ ��������� GostR3410-KeyTransport, ������� ���������� ���������� �������������� ���������
    // � ��������� ��������� ����� ���������. ����� ���������� �� ������ ���� ��������� ��������� ���������� ����,
    // ������� ��������� ������������� ��������� �����������.
    // transportBlob ��� ������������� ����� ��������� � �������� ���� � ������� ��� ���������� ASN1, ��������,
    // https://lapo.it/asn1js/  - ������
    // https://www.codeproject.com/Articles/4910/ASN-Editor - �������
    transportBlob :=
       [$30, $81, $A4, $30, $28, $04, $20] +
       sessionKey +
       [$04, $04] +
       sessionMAC +
       [$A0, $78, $06, $07, $2A, $85, $03, $02, $02, $1F, $01, $A0, $63, $30, $1C, $06,
        $06, $2A, $85, $03, $02, $02, $13, $30, $12, $06, $07, $2A, $85, $03, $02, $02,
        $24, $00, $06, $07, $2A, $85, $03, $02, $02, $1E, $01, $03, $43, $00, $04, $40
       ] +
       publicKey +
       [$04, $08] +
       sessionSV;

    // ��������� �� ����������� ����� ��������� ������� �������������. ����� �� �������������
    // � �������������� ��������� (��. ����)
    CheckCryptoCall(CryptGetKeyParam(hSessionKey, KP_IV, nil, @size, 0));
    SetLength(initVector, size);
    CheckCryptoCall(CryptGetKeyParam(hSessionKey, KP_IV, @initVector[0], @size, 0));

    // ��������� ������ ���������� CBC
    keyParam := CRYPT_MODE_CBC;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_MODE, @keyParam, 0));

    // ��� �������������, ���������� ���������� ����� �������� (������������) ��������� �������
    //
    //keyParam := 0;
    //CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_PADDING, @keyParam, 0));
    //
    // � ��������� ������� ������������ ����������� �������, ����� ����������

    // ��������� �������� �������� SOAP-�������, ������� ����� ���������� ����� ��������� ����������.
    encryptedData := TEncoding.Default.GetBytes(ASOAPRequest.DocumentElement.XML);

    // ����������� ������� ���������������� SOAP-�������.
    sourceDataLen := Length(encryptedData);
    encryptDataLen := sourceDataLen;

    // ���������� �������� SOAP-�������
    CryptEncrypt(hSessionKey, 0, true, 0, nil, @encryptDataLen, 0);
    SetLength(encryptedData, encryptDataLen);
    CryptEncrypt(hSessionKey, 0, true, 0, @encryptedData[0], @sourceDataLen, encryptDataLen);

    // ������������ ��������� �������������� SOAP-�������.
    SetEncryptedContent(ASOAPRequest, initVector + encryptedData,
                          transportBlob, GetProviderPublicCertificate(ACryptoProvider));
  finally
    if hSessionKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hSessionKey));

    if hAgreeKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hAgreeKey));

    if hEphemeralKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hEphemeralKey));

    SetLength(sessionKeyBlob, 0);
    SetLength(providerPublicKeyBlob, 0);
    SetLength(transportBlob, 0);
    SetLength(sessionSV, 0);
    SetLength(sessionKey, 0);
    SetLength(sessionMAC, 0);
    SetLength(initVector, 0);
    SetLength(encryptedData, 0);
  end;
end;

// ������������ SOAP-������
class function TCrypto.DecryptSOAPResponse(ACryptoProvider: HCRYPTPROV; ASOAPResponse: IXMLDocument): string;
var
  remotePublicKeyBlob, remoteSessionKeyBlob,
  responseData, initVector,
  decryptedData: TBytes;
  hPrivateKey, hAgreeKey,
  hSessionKey: HCRYPTKEY;
  decryptedDataLen,
  keyParam: DWORD;
begin
  try
    // ��������� ���������� ��������� �����
    CheckCryptoCall(CryptGetUserKey(ACryptoProvider, AT_KEYEXCHANGE, @hPrivateKey));

    // ������������ BLOB-�� ���������� � ����������� ������ ��� �� ������ �������������� ����� �� ������ ���
    GetResponseKeysBlobs(ASOAPResponse, remotePublicKeyBlob, remoteSessionKeyBlob);

    // ��������� ����� ������������ �������� ��������� ����� ��� (�����������)
    // �� ��������� �������� ����� (����������)
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remotePublicKeyBlob[0], Length(remotePublicKeyBlob), hPrivateKey, 0, @hAgreeKey));

    // ��������� ��������� PRO_EXPORT ��������� ����� ������������
    keyParam := CALG_PRO_EXPORT;
    CheckCryptoCall(CryptSetKeyParam(hAgreeKey, KP_ALGID, @keyParam, 0));

    // ��������� ����������� ����� �������� ����������� ����� ��� (�����������)
    // �� ����� ������������
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remoteSessionKeyBlob[0], Length(remoteSessionKeyBlob), hAgreeKey, 0, @hSessionKey));

    // ��������� ������ ���������� CBC
    keyParam := CRYPT_MODE_CBC;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_MODE, @keyParam, 0));

    // ��������� ������ ��������
    keyParam := 0;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_PADDING, @keyParam, 0));

    // ��������� ������������� ������ �� ������ ���
    responseData := GetEncryptedResponseDataBlob(ASOAPResponse);

    // ��������� ������� ������������� (������ 8 ���� ������)
    initVector := Copy(responseData, 0, 8);
    // ���������� �������������� �������� SOAP-�������
    decryptedData := Copy(responseData, 8, Length(responseData) - 8);

    // ��������� ������� �������������
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_IV, @initVector[0], 0));

    // ����������� ������� ������ �������������� �������� SOAP-�������
    decryptedDataLen := Length(decryptedData);

    // ������������ �������������� �������� SOAP-�������, ����� �������� �
    // decryptedData ����� ��������� ������������� ������,
    // � decryptedDataLen - ����� �������������� ������
    CheckCryptoCall(CryptDecrypt(hSessionKey, 0, true, 0, @decryptedData[0], @decryptedDataLen));

    // ���������� ������� ������ �������������� �������� SOAP-�������
    SetLength(decryptedData, decryptedDataLen);

    // ������������ ��������� ���������� �������� SOAP-������� (���������� ����������� �������� � �.�.)
    Result := CreateDecryptedContent(decryptedData);
  finally
    if hSessionKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hSessionKey));

    if hAgreeKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hAgreeKey));

    if hPrivateKey <> 0 then
      CheckCryptoCall(CryptDestroyKey(hPrivateKey));

    SetLength(remoteSessionKeyBlob, 0);
    SetLength(remotePublicKeyBlob, 0);
    SetLength(initVector, 0);
    SetLength(decryptedData, 0);
  end;
end;

// ����������� ������ ������ ���-������� ��� � ����������� SOAP-��������
class procedure TCrypto.FssOnBeforeExecute(const MethodName: string; SOAPRequest: TStream);
var
  hCryptoProvider: HCRYPTPROV;
  soapRequestDoc, signEnvelopeDoc: IXMLDocument;
begin
  try
    soapRequestDoc := TXMLDocument.Create(nil);
    soapRequestDoc.LoadFromStream(SOAPRequest);
    signEnvelopeDoc := LoadXMLDocument(ExtractFilePath(Application.ExeName) + 'regiemk_fss_sign_envelope.xml');

    InitContext(@hCryptoProvider, PROV_GOST_2001_DH, 'KeyContainer');

    PrepareSOAPRequest(soapRequestDoc, signEnvelopeDoc);
    SignSOAPRequest(hCryptoProvider, signEnvelopeDoc);
    EncryptSOAPRequest(hCryptoProvider, ExtractFilePath(Application.ExeName) + 'fss.cer', signEnvelopeDoc);

    FormatStream(SOAPRequest, signEnvelopeDoc.DocumentElement.XML);
  finally
    signEnvelopeDoc := nil;
    signEnvelopeDoc := nil;

    if hCryptoProvider <> 0 then
      ReleaseContext(hCryptoProvider);
  end;
end;

// ����������� ����������� ������ ��� �� ����� ������ ���-������� ��� � ������������� SOAP-��������
class procedure TCrypto.FssOnAfterExecute(const MethodName: string; SOAPResponse: TStream);
var
  hCryptoProvider: HCRYPTPROV;
  responseDoc: IXMLDocument;
  descryptedResponse: string;
begin
  try
    responseDoc := TXMLDocument.Create(nil);
    responseDoc.LoadFromStream(SOAPResponse);

    InitContext(@hCryptoProvider, PROV_GOST_2001_DH, 'KeyContainer');

    // �������� ������ ������� ������ ��� ��������� ����������� ���������������� �������������� �������
    if Not CheckFailedResponse(responseDoc) then
    begin
      descryptedResponse := DecryptSOAPResponse(hCryptoProvider, responseDoc);

      FormatStream(SOAPResponse, descryptedResponse);
    end;
  finally
    responseDoc := nil;

    if hCryptoProvider <> 0 then
      ReleaseContext(hCryptoProvider);
  end;
end;

end.
