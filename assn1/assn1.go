package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
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
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
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

// The structure definition for a user record
type User struct {
	Username string;
	RSAPrivateKey userlib.PrivateKey;
	EnKey []byte; // To encrypt MetaFile struct
	UUID string;
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type MetaFile struct {
	MyKey string;
	EnKey []byte; // To encrypt File struct
	FilePointer string; // Pointer to the corresponding File struct
}

type File struct {
	Type string ; // whether this is a file or just the metadata
	OwnersUUID string;
	EnKey []byte; // To encrypt file data
	DataPointer string; // The head of the file data
}

type FileData struct {
	Type string; // whether this is a file or just the metadata
	Value []byte; // data
	Length int; // whether this file is shared or not
	NextPointer string; // Hash to the next pointer
	NextEnKey []byte; // encryption key for the next block in the chain
}

func StoreEncryptedData(key string, value []byte, enKey []byte) {
	ciphertext := make([]byte, userlib.BlockSize + len(value));
	iv := userlib.RandomBytes(userlib.BlockSize);
	ciphertext[:userlib.BlockSize] = iv;
	stream := userlib.CFBEncrypter(enKey, iv);
	stream.XORKeyStream(ciphertext[userlib.BlockSize:], value);
	
	//For integrity check
	intergrityH := userlib.NewHMAC(byte[]("nokey"))
	intergrityH.Write(byte[](ciphertext));
	value := append(intergrityH.Sum(nil), ciphertext)

	//Storing Data in DataStore
	userlib.DatastoreSet(datastoreKey, value);
}

func LoadDecryptedData(key string, enKey []byte) ([]byte, error) {
	value, ok := userlib.DatastoreGet(datastoreKey);
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
		return nil, errors.New(strings.ToTitle("Data Tampered"));
	}
	
	//Decrypt Data
	iv := ciphertext[:userlib.BlockSize];
	ciphertext = ciphertext[aes.BlockSize:]
	stream := userlib.CFBDecrypter(enKey, iv);
	stream.XORKeyStream(ciphertext, ciphertext);
	return ciphertext, nil;
}

func ReadFileStruct(key string, enKey []byte) (File, error) {
	var filedata File;
	var mData []byte;
	var _err error;

	for {
		//Loading File struct
		mData, _err = LoadDecryptedData(key, enKey);
		if _err != nil {
			return nil, nil, nil, _err;
		}

		//unmarshalling data
		json.Unmarshal(mData, &filedata);

		if filedata.Type == "notShared" {
			return key, enKey, filedata, nil;
		}

		key = filedata.DataPointer;
		enKey = filedata.EnKey;
	}

	return nil, nil, nil, errors.New(strings.ToTitle("Data Tampered"));
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
	key, _ = userlib.GenerateRSAKey();

	//Storing publicKey in Keystore
	userlib.KeystoreSet(username, key.PublicKey);
	
	//Populating User data structure
	var userdata User;
	userdata.Username = username;
	userdata.RSAPrivateKey = *key;
	userdata.UUID = uuid.New().String();
	userdata.EnKey = userlib.RandomBytes(userlib.AESKeySize)
	
	//Making Key for DataStore
	datastoreKey := string(userlib.Argon2Key([]byte(password), []byte(username), userlib.HashSize));
	
	//Marshalling and storing Data
	mData, _ := json.Marshal(userdata);
	enKey := []byte(userlib.Argon2Key([]byte(password), []byte("nosalt"), userlib.AESKeySize));
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
	datastoreKey := string(userlib.Argon2Key([]byte(password), []byte(username), userlib.HashSize));
	enKey := []byte(userlib.Argon2Key([]byte(password), []byte("nosalt"), userlib.AESKeySize));
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
	metaDsKey := string(userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), userlib.HashSize));
	
	//Populating MetaFile struct
	var metaFdata MetaFile;
	metaFdata.MyKey = metaDsKey;
	metaFdata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	metaFdata.FilePointer = string(userlib.RandomBytes(userlib.HashSize));

	//Populating File struct
	var filedata File;
	filedata.Type = "notShared";
	filedata.OwnersUUID = userdata.UUID;
	filedata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	filedata.DataPointer = string(userlib.RandomBytes(userlib.HashSize));

	//Populating FileData struct
	var fileDdata FileData;
	fileDdata.Type = "value";
	fileDdata.Value = data;
	fileDdata.Length = len(data);
	fileDdata.NextPointer = nil;
	fileDdata.NextEnKey = nil;
	
	//Marshalling and storing FileData struct
	mData, _ := json.Marshal(fileDdata);
	StoreEncryptedData(filedata.DataPointer, mData, filedata.EnKey);
	
	//Marshalling and storing File struct
	mData, _ = json.Marshal(filedata);
	StoreEncryptedData(metaFdata.FilePointer, mData, metaFdata.EnKey);
	
	//Marshalling and storing MetaFile struct
	mData, _ = json.Marshal(metaFdata);
	StoreEncryptedData(metaDsKey, mData, userdata.EnKey);
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//Making MetaFile Key for DataStore
	metaDsKey := string(userlib.Argon2Key([]byte(userdata.UUID), []byte(filename), userlib.HashSize));
	
	//Loading MetaFile struct
	mData, _err := LoadDecryptedData(metaDsKey, userdata.EnKey);
	if _err != nil {
		return _err;
	}

	//unmarshalling data
	var metaFdata MetaFile;
	json.Unmarshal(mData, &metaFdata);

	//checking the integrity of MetaFile
	if metaDsKey != metaFdata.MyKey {
		return errors.New(strings.ToTitle("Data Tampered"));
	}

	//Now we have to read until multiple data blocks if this is a shared block 
	//Loading File struct
	var filedata File;
	var filedataKey string;
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
	filedata.EnKey = userlib.RandomBytes(userlib.AESKeySize);
	filedata.DataPointer = string(userlib.RandomBytes(userlib.HashSize));
	
	//Marshalling and storing FileData struct
	mData, _ = json.Marshal(fileDdata);
	StoreEncryptedData(filedata.DataPointer, mData, filedata.EnKey);
	
	//Marshalling and storing File struct
	mData, _ = json.Marshal(filedata);
	StoreEncryptedData(filedataKey, mData, filedataEnKey);

	return nil;
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
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
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
