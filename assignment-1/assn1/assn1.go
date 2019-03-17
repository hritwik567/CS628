// changed the packag name from assn1 to main
// package main
package assn1
// ------------------IMP------------

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	
	// Arpit: remove fmt and main func
	//"fmt"
	// -----------------IMP-----------	

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	// changed the pulled userlib on line 25 (removed "=")
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	key, _ := userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}
func BytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}

// The structure definition for a user record
type User struct {
	Username string;
	RSAPrivateKey userlib.PrivateKey;
	// Arpit: Shouldn't the encryption key be unique for every 
	// Metafile struct
	// Hritvik: We are not sharing this key with anyone so we don't have any problem
	EnKey []byte; // To encrypt MetaFile struct
	// Arpit: type of UUID should be uuid.UUID, I think
	// Hritvik: It is easy to use this as a string 
	// also I think uuid.UUID is typedef string
	// Arpit: check bytesToUUID function. It is used 
	// similar function. Anyway it's something to note while 
	// debugging
	UUID string;
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type MetaFile struct {
	MyKey []byte;
	EnKey []byte; // To encrypt File struct
	FilePointer []byte; // Pointer to the corresponding File struct
}

type File struct {
	Type string ; // whether this is a file or just the metadata
	// Arpit: type of UUID. Though, it doesn't matter much
	OwnersUUID string;
	EnKey []byte; // To encrypt file data
	DataPointer []byte; // The head of the file data
}

type FileData struct {
	Type string; // whether this is a file or just the metadata
	Value []byte; // data
	Length int; // whether this file is shared or not
	NextPointer []byte; // Hash to the next pointer
	NextEnKey []byte; // encryption key for the next block in the chain
}

func StoreEncryptedData(key []byte, value []byte, enKey []byte) {
	Tkey := string(key);
	ciphertext := make([]byte, userlib.BlockSize + len(value));
	// Not sure otherwise gives compilatioon error
	iv := userlib.RandomBytes(userlib.BlockSize);
	copy(ciphertext[:userlib.BlockSize], iv);
	stream := userlib.CFBEncrypter(enKey, iv);
	stream.XORKeyStream(ciphertext[userlib.BlockSize:], value);
	
	//For integrity check
	intergrityH := userlib.NewHMAC([]byte("nokey"))
	intergrityH.Write([]byte(ciphertext));
	value = append(intergrityH.Sum(nil), ciphertext...)
	//Storing Data in DataStore
	userlib.DatastoreSet(Tkey, value);
}

func LoadDecryptedData(key []byte, enKey []byte) ([]byte, error) {
	Tkey := string(key);
	value, ok := userlib.DatastoreGet(Tkey);
	if !ok {
		return nil, errors.New(strings.ToTitle("Key Does Not Exist"));
	}
	
	//Length checking of the value
	if len(value) < userlib.HashSize + userlib.BlockSize {
		return nil, errors.New(strings.ToTitle("Data Length Tampered"));
	}
	
	//intergrity check
	intergrityH := value[:userlib.HashSize];
	ciphertext := value[userlib.HashSize:];
	ciphertextH := userlib.NewHMAC([]byte("nokey"));
	ciphertextH.Write(ciphertext);
	if !userlib.Equal(intergrityH, ciphertextH.Sum(nil)) {
		return nil, errors.New(strings.ToTitle("Data Tampered 1"));
	}
	
	//Decrypt Data
	iv := ciphertext[:userlib.BlockSize];
	ciphertext = ciphertext[userlib.BlockSize:]
	stream := userlib.CFBDecrypter(enKey, iv);
	stream.XORKeyStream(ciphertext, ciphertext);
	return ciphertext, nil;
}


// Arpit: return value should also include key & EnKey in declaration below - DONE
func ReadFileStruct(key []byte, enKey []byte) ([]byte, []byte, File, error) {
	var filedata File;
	var mData []byte;
	var _err error;
	for {
		//Loading File struct
		mData, _err = LoadDecryptedData(key, enKey);
		if _err != nil {
			return make([]byte, 0), mData, filedata, _err;
		}

		//unmarshalling data
		json.Unmarshal(mData, &filedata);

		if filedata.Type == "notShared" {
			return key, enKey, filedata, nil;
		}

		key = filedata.DataPointer;
		enKey = filedata.EnKey;
	}

	return make([]byte, 0), mData, filedata, errors.New(strings.ToTitle("Data Tampered"));
}
// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	_, ok := userlib.KeystoreGet(username);
	if ok {
		return nil, errors.New(strings.ToTitle("User already registered"));
	}

	//Generating RSA key pair
	key, _ := userlib.GenerateRSAKey();

	//Storing publicKey in Keystore
	userlib.KeystoreSet(username, key.PublicKey);
	
	//Populating User data structure
	var userdata User;
	userdata.Username = username;
	// Arpit: just reconfirm the way private key is assigned
	userdata.RSAPrivateKey = *key;
	userdata.UUID = uuid.New().String();
	userdata.EnKey = userlib.RandomBytes(userlib.AESKeySize)
	
	//Making Key for DataStore
	datastoreKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSize));
	
	//Marshalling and storing Data
	mData, err := json.Marshal(userdata);
	if err != nil {
		return nil, err;
	}
	enKey := userlib.Argon2Key([]byte(password), []byte("nosalt"), uint32(userlib.AESKeySize));
	StoreEncryptedData(datastoreKey, mData, enKey);
	
	//Encrypting Data
	return &userdata, nil;
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	_, ok := userlib.KeystoreGet(username);
	if !ok {
		return nil, errors.New(strings.ToTitle("User Does Not Exist"));
	}

	//Loading data
	datastoreKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSize));
	enKey := userlib.Argon2Key([]byte(password), []byte("nosalt"), uint32(userlib.AESKeySize));
	mData, _err := LoadDecryptedData(datastoreKey, enKey);
	if _err != nil {
		return nil, _err;
	}

	//unmarshalling data
	var userdata User;
	json.Unmarshal(mData, &userdata);
	return &userdata, nil;
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//Making MetaFile Key for DataStore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	
	//Populating MetaFile struct
	var metaFdata MetaFile;
	metaFdata.MyKey = metaDsKey;
	metaFdata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	metaFdata.FilePointer = userlib.RandomBytes(userlib.HashSize);

	userlib.DebugMsg("StoreFile Debug Message", []byte(metaDsKey), []byte(metaFdata.MyKey));
	//Populating File struct
	var filedata File;
	filedata.Type = "notShared";
	filedata.OwnersUUID = userdata.UUID;
	filedata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	filedata.DataPointer = userlib.RandomBytes(userlib.HashSize);

	//Populating FileData struct
	var fileDdata FileData;
	fileDdata.Type = "value";
	fileDdata.Value = data;
	fileDdata.Length = len(data);
	fileDdata.NextPointer = make([]byte, 0);
	fileDdata.NextEnKey = make([]byte, 0);
	
	//Marshalling and storing FileData struct
	mData, err := json.Marshal(fileDdata);
	if err != nil {
		return;
	}
	StoreEncryptedData(filedata.DataPointer, mData, filedata.EnKey);
	
	//Marshalling and storing File struct
	mData, err = json.Marshal(filedata);
	if err != nil {
		return;
	}
	StoreEncryptedData(metaFdata.FilePointer, mData, metaFdata.EnKey);
	
	//Marshalling and storing MetaFile struct
	mData, err = json.Marshal(metaFdata);
	if err != nil {
		return;
	}
	StoreEncryptedData(metaDsKey, mData, userdata.EnKey);
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//Making MetaFile Key for DataStore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	
	//Loading MetaFile struct
	mData, _err := LoadDecryptedData(metaDsKey, userdata.EnKey);
	if _err != nil {
		return _err;
	}

	//unmarshalling data
	var metaFdata MetaFile;
	json.Unmarshal(mData, &metaFdata);

	//checking the integrity of MetaFile
	if !BytesEqual(metaDsKey, metaFdata.MyKey) {
		return errors.New(strings.ToTitle("Data Tampered"));
	}

	//Now we have to read until multiple data blocks if this is a shared block 
	//Loading File struct
	var filedata File;
	var filedataKey []byte;
	var filedataEnKey []byte;
	filedataKey, filedataEnKey, filedata, _err = ReadFileStruct(metaFdata.FilePointer, metaFdata.EnKey);
	if _err != nil {
		return _err;
	}

	//Populating FileData struct
	var fileDdata FileData;
	fileDdata.Type = "value";
	fileDdata.Value = data;
	fileDdata.Length = len(data);
	fileDdata.NextPointer = filedata.DataPointer;
	fileDdata.NextEnKey = filedata.EnKey;
	
	//Finding address and encryption key for the new block
	// Arpit -> Arpit: check size below
	filedata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	filedata.DataPointer = userlib.RandomBytes(userlib.HashSize);
	
	//Marshalling and storing FileData struct
	mData, err = json.Marshal(fileDdata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(filedata.DataPointer, mData, filedata.EnKey);
	
	//Marshalling and storing File struct
	mData, err = json.Marshal(filedata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(filedataKey, mData, filedataEnKey);

	return nil;
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Making MetaFile Key for Datastore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	
	// Loading Metafile struct
	mData, _err := LoadDecryptedData(metaDsKey, userdata.EnKey);
	if _err != nil {
		return nil, _err;
	}
	
	// Unmarshalling data
	var metaFdata MetaFile;
	json.Unmarshal(mData, &metaFdata);

	// Integrity check
	// userlib.DebugMsg("Debug Message", []byte(metaDsKey), []byte(metaFdata.MyKey));

	if !BytesEqual(metaDsKey, metaFdata.MyKey) {
		return nil, errors.New(strings.ToTitle("Data Tempered 2"));
	}
	
	// Now read until finally owner's File struct is found
	// Loading File struct
	var filedata File;
	_, _, filedata, _err = ReadFileStruct(metaFdata.FilePointer, 
												 metaFdata.EnKey);
	if _err != nil {
		return nil, _err;
	}

	unmarshalledDataStruct, _err := LoadDecryptedData(filedata.DataPointer, filedata.EnKey);
	if _err != nil {
		return nil, _err;
	}
	
	var fileDataStruct FileData;
	json.Unmarshal(unmarshalledDataStruct, &fileDataStruct);
	data = fileDataStruct.Value;
	
	// Load all the values from the linked list
	for {
		// Not the correct way
		if len(fileDataStruct.NextPointer) == 0 {
			break;
		}
		unmarshalledDataStruct, _err = LoadDecryptedData(fileDataStruct.NextPointer,
										fileDataStruct.NextEnKey);
		if _err != nil {
			return nil, _err;
		}
		json.Unmarshal(unmarshalledDataStruct, &fileDataStruct);
		data = append(fileDataStruct.Value, data...);
	}

	return data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	EnKey []byte; // To encrypt File struct
	FilePointer []byte; // Pointer to the corresponding File struct
}

type sharedData struct {
	Sign []byte;
	Message []byte;
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	
	//Making MetaFile Key for DataStore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	
	//Loading MetaFile struct
	mData, _err := LoadDecryptedData(metaDsKey, userdata.EnKey);
	if _err != nil {
		return msgid, _err;
	}

	//unmarshalling data
	var metaFdata MetaFile;
	json.Unmarshal(mData, &metaFdata);

	//checking the integrity of MetaFile
	if !BytesEqual(metaDsKey, metaFdata.MyKey) {
		return msgid, errors.New(strings.ToTitle("Data Tampered"));
	}

	//Loading Address and EnKey of the File struct
	var filedataKey []byte;
	var filedataEnKey []byte;
	filedataKey, filedataEnKey, _, _err = ReadFileStruct(metaFdata.FilePointer, metaFdata.EnKey);
	if _err != nil {
		return msgid, _err;
	}
	
	var sharing sharingRecord;
	sharing.FilePointer = filedataKey;
	sharing.EnKey = filedataEnKey;

	mData, err = json.Marshal(sharing);
	if err != nil {
		return (""), err;
	}
	
	pubKey, ok := userlib.KeystoreGet(recipient);
	if !ok {
		return msgid, errors.New(strings.ToTitle("Recipient Does Not Exist"));
	}
	
	//encrypting
	rsaEncrypted, _err := userlib.RSAEncrypt(&pubKey, mData, []byte("Tag"));
	if _err != nil {
		return msgid, errors.New(strings.ToTitle("Could not Encrypt"));
	}
	
	//signing
	sign, _err := userlib.RSASign(&(userdata.RSAPrivateKey), rsaEncrypted);
	if _err != nil {
		return msgid, errors.New(strings.ToTitle("RSA sign failure"));
	}
	
	var sharingMsg sharedData;
	sharingMsg.Sign = sign;
	sharingMsg.Message = rsaEncrypted;
	userlib.DebugMsg("Debug Message Share", sharingMsg);
	
	tempMsgid, err := json.Marshal(sharingMsg);
	if err != nil {
		return (""), err;
	}
	userlib.DebugMsg("Debug Message Share Marshelled", tempMsgid);

	return string(tempMsgid), nil;
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	
	pubKey, ok := userlib.KeystoreGet(sender);
	if !ok {
		return errors.New(strings.ToTitle("Sender Does Not Exist"));
	}
	
	userlib.DebugMsg("Debug Message Recive", msgid);
	var sharingMsg sharedData;
	json.Unmarshal([]byte(msgid), &sharingMsg);
	userlib.DebugMsg("Debug Message Recive", sharingMsg.Sign, sharingMsg.Message);

	//verifying the signature
	_err := userlib.RSAVerify(&pubKey, sharingMsg.Message, sharingMsg.Sign);
	if _err != nil {
		return errors.New(strings.ToTitle("RSA verification failure"));
	}
	
	//decrypting
	decrypt, _err := userlib.RSADecrypt(&(userdata.RSAPrivateKey), sharingMsg.Message, []byte("Tag"))
	if _err != nil {
		return errors.New(strings.ToTitle("RSA decryption failure"));
	}
	
	var sharing sharingRecord;
	json.Unmarshal(decrypt, &sharing);
	
	//Making MetaFile Key for DataStore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	
	//Populating MetaFile struct
	var metaFdata MetaFile;
	metaFdata.MyKey = metaDsKey;
	metaFdata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	metaFdata.FilePointer = userlib.RandomBytes(userlib.HashSize);

	//Populating File struct
	var filedata File;
	filedata.Type = "shared";
	filedata.OwnersUUID = userdata.UUID;
	filedata.EnKey = sharing.EnKey;
	filedata.DataPointer = sharing.FilePointer;

	//Marshalling and storing File struct
	mData, err := json.Marshal(filedata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(metaFdata.FilePointer, mData, metaFdata.EnKey);
	
	//Marshalling and storing MetaFile struct
	mData, err = json.Marshal(metaFdata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(metaDsKey, mData, userdata.EnKey);

	return nil;
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// Check if the user is owner of given file
	// Making MetaFile Key for DataStore
	metaDsKey := userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), uint32(userlib.HashSize));
	mData, _err := LoadDecryptedData(metaDsKey, userdata.EnKey);
	if _err != nil {
		return _err;
	}
	
	// Unmarshalling data
	var metaFdata MetaFile;
	json.Unmarshal(mData, &metaFdata);
	
	// Integrity check
	if !BytesEqual(metaDsKey, metaFdata.MyKey) {
		return errors.New(strings.ToTitle("Data Tempered"));
	}	
	
	// Loading File struct
	unmarshalledFileStruct, _err := LoadDecryptedData(metaFdata.FilePointer, metaFdata.EnKey);
	if _err != nil {
		return _err;
	}
	var file File;
	json.Unmarshal(unmarshalledFileStruct, &file);
	if !(strings.Compare(file.OwnersUUID, userdata.UUID) == 0) {
		return errors.New(strings.ToTitle("Permission Denied: Not the owner of file"));
	}
	
	// Load data of the file	
	unmarshalledData, _err := LoadDecryptedData(file.DataPointer, file.EnKey);
	if _err != nil {
		return _err;
	}
	var fileData FileData;
	json.Unmarshal(unmarshalledData, &fileData);
	data := fileData.Value;
	userlib.DatastoreDelete(string(file.DataPointer));
	for {
		if len(fileData.NextPointer) == 0 {
			break;
		}
		unmarshalledData, _err = LoadDecryptedData(fileData.NextPointer, 
								 fileData.NextEnKey);
		userlib.DatastoreDelete(string(fileData.NextPointer));
		if _err != nil {
			return _err;
		}
		json.Unmarshal(unmarshalledData, &fileData);
		data = append(fileData.Value, data...);
	}	
	
	// Arpit -> Arpit : call StoreFile if you can now since it's the same code
	// Store file as a new file with the same metafile and everything else new
	// Arpit: Is there any method to delete old structs?
	// Populating MetaFile struct
	userlib.DatastoreDelete(string(metaFdata.FilePointer));
	metaFdata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	metaFdata.FilePointer = userlib.RandomBytes(userlib.HashSize);

	// Populating File struct
	file.Type = "notShared";
	file.OwnersUUID = userdata.UUID;
	file.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	file.DataPointer = userlib.RandomBytes(userlib.HashSize);

	// Populating FileData struct
	var fileDdata FileData;
	fileDdata.Type = "value";
	fileDdata.Value = data;
	fileDdata.Length = len(data);
	fileDdata.NextPointer = make([]byte, 0);
	fileDdata.NextEnKey = make([]byte, 0);
	
	// Marshalling and storing FileData struct
	mData, err = json.Marshal(fileDdata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(file.DataPointer, mData, file.EnKey);
	
	// Marshalling and storing File struct
	mData, err = json.Marshal(file);
	if err != nil {
		return err;
	}
	StoreEncryptedData(metaFdata.FilePointer, mData, metaFdata.EnKey);
	
	// Marshalling and storing MetaFile struct
	mData, err = json.Marshal(metaFdata);
	if err != nil {
		return err;
	}
	StoreEncryptedData(metaDsKey, mData, userdata.EnKey);

	return nil;
}
