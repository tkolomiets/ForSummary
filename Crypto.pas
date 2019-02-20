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

// Получение контекста крипто-провайдера
class procedure TCrypto.InitContext(ACryptoPovider: PHCRYPTPROV;
           ACryptoPoviderType: integer; ACryptoPoviderContainer: PWideChar);
begin
  CheckCryptoCall(CryptAcquireContext(ACryptoPovider, ACryptoPoviderContainer, '', ACryptoPoviderType, 0));
end;

class procedure TCrypto.ReleaseContext(ACryptoPovider: HCRYPTPROV);
begin
  CheckCryptoCall(CryptReleaseContext(ACryptoPovider, 0));
end;

// Вычисление хэша данных
class function TCrypto.CreateHash(ACryptoProvider: HCRYPTPROV; AData: string): HCRYPTHASH;
var
  sCanonicalizedData, error: string;
  pCanonicalizedData: PSafeArray;
  aByte: TBytes;
  i, count, max: integer;
  res : HRESULT;
begin
  try
    // Канонинзация данных на основе COM-объекта канонизации (c#)

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
        raise Exception.CreateFmt('Канонизация данных хэша: %s.', [error]);
    end;

    i := sCanonicalizedData.LastIndexOf('>');
    sCanonicalizedData := sCanonicalizedData.Substring(0, i + 1);
    aByte := TEncoding.Utf8.GetBytes(sCanonicalizedData);

    // Вычисление хэша на основе канонизированных данных

    CheckCryptoCall(CryptCreateHash(ACryptoProvider, CALG_GR3411, 0, 0, @Result));
    CheckCryptoCall(CryptHashData(Result, PByte(aByte), Length(aByte), 0));
  finally
    SetLength(aByte, 0);
    SafeArrayDestroy(pCanonicalizedData)
  end;
end;

// Вычисление данных по хэшу.
// Например, для помещения его далее в XML-узел документа.
class function TCrypto.GetHashValue(AHash: HCRYPTHASH): TBytes;
var
  pbHash: PBYTE;
  hashSize, dwSize: DWORD;
begin
  // Вычисление размерности указателя на буфер значения хэша
  dwSize := sizeof(DWORD);
  CheckCryptoCall(CryptGetHashParam(AHash, HP_HASHSIZE, @hashSize, @dwSize, 0));

  try
    // Выделение памяти под указатель на буфер значения хэша
    GetMem(pbHash, hashSize);
    // Получение значения хэша и его размера
    CheckCryptoCall(CryptGetHashParam(AHash, HP_HASHVAL, pbHash, @hashSize, 0));

    // Выделение памяти для значения хэша
    SetLength(Result, hashSize);
    Move(pbHash^, Result[0], hashSize);
  finally
    if Assigned(pbHash) then
      FreeMem(pbHash);
  end;
end;

// Наложение ЭП на вычисленный заранее хэша данных
class function TCrypto.CreateSignature(AHash: HCRYPTHASH): TBytes;
var
  hashSize: DWORD;
  pbHash: PBYTE;
  aByte: TBytes;
begin
  // Вычисление размера ЭП хэша данных
  hashSize := 0;
  CheckCryptoCall(CryptSignHash(AHash, AT_KEYEXCHANGE, nil, 0, nil, @hashSize));

  if hashSize > 0 then
    try
      GetMem(pbHash, hashSize);
      // Наложение ЭП хэша данных
      CheckCryptoCall(CryptSignHash(AHash, AT_KEYEXCHANGE, nil, 0, pbHash, @hashSize));

      SetLength(aByte, hashSize);
      Move(pbHash^, aByte[0], hashSize);

      // Реверсирование контента (обратный порядок байт). По неизвестной причине это требуется
      // для корректной обработки подписи в ФСС. Видимо, связано с работой их криптопровайдера.
      Result := ReverseArray(aByte);
    finally
      if Assigned(pbHash) then
        FreeMem(pbHash);

      SetLength(aByte, 0)
    end;
end;

// Получение сертификата открытого ключа из контейнера криптопровайдера
class function TCrypto.GetProviderPublicCertificate(ACryptoProvider: HCRYPTPROV): string;
var
  hPrivateKey: HCRYPTKEY;
  size: DWORD;
  certData: TBytes;
begin
  Result := '';

  try
    // Получение закрытого ключа криптопровайдера
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

// Реверсирование контента подписи (обратный порядок байт)
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
  // c# COM-объектЮ реализация канонизатора
  fCanonicalizer := CoXmlCanonicalizer.Create;
end;

class procedure TCrypto.Release;
begin
  fCanonicalizer := nil;
end;

// Получение BLOB-а открытого ключа получателя зашифрованных сообщений
// - ARemoteCertPath - путь к сертификату открытого ключа получателя зашифрованных сообщений
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

    // Импорт информации по открытому ключу ФСС
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

// Замена содержимого TStream на новое
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

// Формирование структуры EncryptedData зашифрованного SOAP-сообщения
// - AEncryptedData подписанный изашифрофанный базовый SOAP-запрос
// - AEncryptedKey - ASN-структура GostR3410-KeyTransport для формирования сессионного ключа дешифровки
//                    на стороне получателя зашифрованного сообщения
// - AProviderCertificate - сертификат открытого ключа, на основе которого было зашифровано сообщение,
//                          (открытый ключ получателя зашифрованного сообщения)
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

// Форматирование дешифрованного контента базового SOAP-запроса
// (устранение последствий паддинга и т.п.)
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


    // сборка SessionKey BLOB из статической части и параметров сессионного ключа
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

// Получение контента зашифрованного базового SOAP-сообщения из структуры
// входящего зашифровнного SOAP-сообщения
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

// Подготовка структуры базового SOAP-запроса к подписи и шифрованию
// ASourceSOAP - базовый SOAP-запрос, результат вызова метода прокси-объекта веб-сервиса
// AFormattedSOAP - шаблон подписанного SOAP-собщения, имеющий подготовленную структуру:
// - служебные заголовки ЭП,
// - необходимые для удаленного получателя атрибуты XML-узлов
// - и т.п.
class procedure TCrypto.PrepareSOAPRequest(ASourceSOAP: IXMLDocument; AFormattedSOAP: IXMLDocument);
var
  bodyNode, fssOperationNode, ogrnNode: IXMLNode;
  i: integer;
begin
  // Выделение из базового SOAP-запроса узла бизнес-операции (например, получение номера ЭЛН)
  fssOperationNode := ASourceSOAP.DocumentElement
                             .ChildNodes[0]  // Body
                             .ChildNodes[0]; // Operation (например, getNewLNNumRange)

  // Выделение из шаблона подписанного SOAP-сообщения тела SOAP-запроса
  bodyNode := AFormattedSOAP.DocumentElement.ChildNodes[1];

  // Формирование узла бизнес-опреации для шаблона подписанного SOAP-сообщения
  bodyNode.ChildNodes.Add(fssOperationNode);

  // Получаем ОГРН организации
  for i := 0 to fssOperationNode.ChildNodes.Count - 1 do
   if AnsiLowerCase(fssOperationNode.ChildNodes[i].LocalName) = 'ogrn' then
     ogrnNode := fssOperationNode.ChildNodes[i];

  // Устанавливаем необходимый ОГРН по всему SOAP-сообщению
  AFormattedSOAP.LoadFromXML(AFormattedSOAP.DocumentElement.XML.Replace('OGRNNUMBER', ogrnNode.Text));
end;

// Подпись SOAP-запроса
class procedure TCrypto.SignSOAPRequest(ACryptoProvider: HCRYPTPROV; ASOAPRequest: IXMLDocument);
var
  headerNode, bodyNode, securityNode,
  signatureNode, signValueNode, signInfoNode,
  referenceNode, digestValueNode, certificateNode: IXMLNode;
  hash: HCRYPTHASH;
  hashValue: TBytes;
begin
  // Выделение необходмых XML-узлов
  headerNode := ASOAPRequest.DocumentElement.ChildNodes[0];
  bodyNode := ASOAPRequest.DocumentElement.ChildNodes[1];
  securityNode := headerNode.ChildNodes[0];
  certificateNode := securityNode.ChildNodes[1];
  signatureNode := securityNode.ChildNodes[0];
  signInfoNode :=  signatureNode.ChildNodes[0];
  signValueNode := signatureNode.ChildNodes[1];
  referenceNode := signInfoNode.ChildNodes[2];
  digestValueNode :=  referenceNode.ChildNodes[2];

  // Формирование дайджеста тела SOAP-запроса (например, getNewLNNumRange)
  try
    // Вычисление дайджеста
    hash := CreateHash(ACryptoProvider, bodyNode.XML);
    hashValue := GetHashValue(hash);

    // Установка BASE64 значения дайджеста в узел digestValue
    digestValueNode.Text := TNetEncoding.Base64.EncodeBytesToString(hashValue);
  finally
    if hash <> 0 then
    begin
      CheckCryptoCall(CryptDestroyHash(hash));
      SetLength(hashValue, 0);
    end;
  end;

  // Наложение ЭП на вычисленный дайджест тела SOAP-запроса.
  try
    // Вычисление ЭП
    hash := CreateHash(ACryptoProvider, signInfoNode.Xml);
    hashValue := CreateSignature(hash);

    // Установка BASE64 значения ЭП в узел signValue
    signValueNode.Text := TNetEncoding.Base64.EncodeBytesToString(hashValue);
  finally
    if hash <> 0 then
    begin
      CheckCryptoCall(CryptDestroyHash(hash));
      SetLength(hashValue, 0);
    end;
  end;

  // Указание сертификата открытого ключа, на основе которого формировалась ЭП.
  certificateNode.Text := GetProviderPublicCertificate(ACryptoProvider);
end;

class function TCrypto.CheckFailedResponse(ASOAPResponse: IXMLDocument): boolean;
var
  node : IXMLNode;
begin
  Result := False;

  // Выделение необходимых XML-узлов
  if ASOAPResponse.DocumentElement.ChildNodes.Count = 1 then
  begin
    node := ASOAPResponse.DocumentElement.ChildNodes[0];

    Result := (node.ChildNodes.Count = 1) And
       (node.ChildNodes[0].LocalName = 'Fault');

  end;
end;

// Шифрование SOAP-запроса
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
    // Формирование эфемерного ключа в качестве локального закрытого ключа
    // отправителя зашифрованного сообщения.
    // В принципе, работать будет и на обычном локальном закрытом ключе (CryptGetUserKey).
    CheckCryptoCall(CryptGenKey(ACryptoProvider, CALG_DH_EL_EPHEM, CRYPT_EXPORTABLE, @hEphemeralKey));

    // Экспорт открытого ключа в BLOB из локального закрытого.
    CheckCryptoCall(CryptExportKey(hEphemeralKey, 0, PUBLICKEYBLOB, 0, nil, @size));
    SetLength(providerPublicKeyBlob, size);
    CheckCryptoCall(CryptExportKey(hEphemeralKey, 0, PUBLICKEYBLOB, 0, @providerPublicKeyBlob[0], @size));

    // Выделение из BLOB-а контента открытого ключа (структуру BLOB-а см. в GetResponseKeysBlobs),
    // который далее пойдет в GostR3410-KeyTransport
    publicKey := Copy(providerPublicKeyBlob, Length(providerPublicKeyBlob) - 64, 64);

    // Получение BLOB открытого ключа удаленного получателя зашифрованного сообщения (ФСС).
    // ARemoteCertPath - путь к сертификату открытого ключа удаленного получателя зашифрованного сообщения,
    // который, часто, публикуется в открытом доступе, на сайте получателя.
    remotePublicKeyBlob := GetRemotePublicKeyBlob(ACryptoProvider, ARemoteCertPath);

    // Получение ключа согласования импортом открытого ключа получателя зашифрованного сообщения (ФСС)
    // на локальном закрытом ключе отправителя зашифрованного сообщения.
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remotePublicKeyBlob[0], Length(remotePublicKeyBlob),
                                       hEphemeralKey, 0, @hAgreeKey));

    // Установка PRO_EXPORT алгоритма ключа согласования
    keyParam := CALG_PRO_EXPORT;
    CheckCryptoCall(CryptSetKeyParam(hAgreeKey, KP_ALGID, @keyParam, 0));

    // Создание случайного сессионного ключа, которым будет зашифровано сообщение.
    CheckCryptoCall(CryptGenKey(ACryptoProvider, CALG_G28147, CRYPT_EXPORTABLE, @hSessionKey));

    // Экспорт сессионного ключа в BLOB
    CheckCryptoCall(CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, nil, @size));
    SetLength(sessionKeyBlob, size);
    CheckCryptoCall(CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, @sessionKeyBlob[0], @size));

    // Выделение из BLOB-а контенты компонент UKM, сессионного ключа, MAC. Структуру BLOB-а см. в GetResponseKeysBlobs.
    sessionSV  := Copy(sessionKeyBlob, 16, 8);
    sessionKey := Copy(sessionKeyBlob, 24, 32);
    sessionMAC := Copy(sessionKeyBlob, 56, 4);

    // Формирование структуры GostR3410-KeyTransport, которая передается получателю зашифрованного сообщения
    // в служебном заголовке этого сообщения. Далее получатель на основе этой структуры формирует сессионный ключ,
    // которым дешифрует зашифрованное сообщение отправителя.
    // transportBlob при необходимости можно сохранить в бинарный файл и открыть его редактором ASN1, например,
    // https://lapo.it/asn1js/  - онлайн
    // https://www.codeproject.com/Articles/4910/ASN-Editor - десктоп
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

    // Получение из сессионного ключа параметра вектора инициализации. Далее он прикрепляется
    // к зашифрованному сообщению (см. ниже)
    CheckCryptoCall(CryptGetKeyParam(hSessionKey, KP_IV, nil, @size, 0));
    SetLength(initVector, size);
    CheckCryptoCall(CryptGetKeyParam(hSessionKey, KP_IV, @initVector[0], @size, 0));

    // Установка режима шифрования CBC
    keyParam := CRYPT_MODE_CBC;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_MODE, @keyParam, 0));

    // При необходимости, необходимо установить режим паддинга (выравнивания) следующим образом
    //
    //keyParam := 0;
    //CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_PADDING, @keyParam, 0));
    //
    // В некоторых случаях выравнивание реализуется вручную, путем добавления

    // Получение контента базового SOAP-запроса, который будет зашифрован перед отправкой получателю.
    encryptedData := TEncoding.Default.GetBytes(ASOAPRequest.DocumentElement.XML);

    // Определение размера незашифрованного SOAP-запроса.
    sourceDataLen := Length(encryptedData);
    encryptDataLen := sourceDataLen;

    // Шифрование базового SOAP-запроса
    CryptEncrypt(hSessionKey, 0, true, 0, nil, @encryptDataLen, 0);
    SetLength(encryptedData, encryptDataLen);
    CryptEncrypt(hSessionKey, 0, true, 0, @encryptedData[0], @sourceDataLen, encryptDataLen);

    // Формирование структуры зашифрованного SOAP-запроса.
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

// Дешифрование SOAP-ответа
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
    // Получение локального закрытого ключа
    CheckCryptoCall(CryptGetUserKey(ACryptoProvider, AT_KEYEXCHANGE, @hPrivateKey));

    // Формирование BLOB-ов публичного и сессионного ключей ФСС на основе зашифрованного ключа из ответа ФСС
    GetResponseKeysBlobs(ASOAPResponse, remotePublicKeyBlob, remoteSessionKeyBlob);

    // Получение ключа согласования импортом открытого ключа ФСС (отправителя)
    // на локальном закрытом ключе (получателя)
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remotePublicKeyBlob[0], Length(remotePublicKeyBlob), hPrivateKey, 0, @hAgreeKey));

    // Установка параметра PRO_EXPORT алгоритма ключа согласования
    keyParam := CALG_PRO_EXPORT;
    CheckCryptoCall(CryptSetKeyParam(hAgreeKey, KP_ALGID, @keyParam, 0));

    // Получение сессионного ключа импортом сессионного ключа ФСС (отправителя)
    // на ключе согласования
    CheckCryptoCall(CryptImportKey(ACryptoProvider, @remoteSessionKeyBlob[0], Length(remoteSessionKeyBlob), hAgreeKey, 0, @hSessionKey));

    // Установка режима шифрования CBC
    keyParam := CRYPT_MODE_CBC;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_MODE, @keyParam, 0));

    // Установка режима паддинга
    keyParam := 0;
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_PADDING, @keyParam, 0));

    // Получение зашифрованных данных из ответа ФСС
    responseData := GetEncryptedResponseDataBlob(ASOAPResponse);

    // Получение вектора инициализации (первые 8 байт ответа)
    initVector := Copy(responseData, 0, 8);
    // Полученние зашифрованного базового SOAP-запроса
    decryptedData := Copy(responseData, 8, Length(responseData) - 8);

    // Установка вектора инициализации
    CheckCryptoCall(CryptSetKeyParam(hSessionKey, KP_IV, @initVector[0], 0));

    // Определение размера буфера зашифрованного базового SOAP-запроса
    decryptedDataLen := Length(decryptedData);

    // Дешифрование зашифрованного базового SOAP-запроса, после которого в
    // decryptedData будет содержать дешифрованные данные,
    // а decryptedDataLen - длину расшифрованных данных
    CheckCryptoCall(CryptDecrypt(hSessionKey, 0, true, 0, @decryptedData[0], @decryptedDataLen));

    // Обновление размера буфера дешифрованного базового SOAP-запроса
    SetLength(decryptedData, decryptedDataLen);

    // Формирование конечного содержания базового SOAP-запроса (устранение последствий паддинга и т.п.)
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

// Перехватчик вызова метода веб-сервиса ФСС с шифрованием SOAP-контента
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

// Перехватчик синхронного ответа ФСС на вызов метода веб-сервиса ФСС с дешифрованием SOAP-контента
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

    // Проверка ответа наличие ошибок при обработке получателем соответствующего зашифрованного запроса
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
