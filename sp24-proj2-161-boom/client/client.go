package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username        string
	PasswordHash    []byte
	Salt            []byte
	PrivateEncKey   userlib.PKEDecKey
	PrivateSignKey  userlib.DSSignKey
	FileTable       map[string]uuid.UUID
	KeyTable        map[string][]byte
	TreeTable       map[string]uuid.UUID
	TreeKeyTable    map[string][]byte
	InvitationTable map[string]uuid.UUID

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	FileUUID uuid.UUID
	FileList []uuid.UUID
	//inviteUUID uuid.UUID
}

type FilePointer struct {
	Content []byte
}

type Invitation struct {
	FileUUID uuid.UUID
	//TODO change to uuid mayhaps
	FileEncKey  []byte
	FileSignKey []byte
	TreeUUID    uuid.UUID
	TreeEncKey  []byte
	TreeSignKey []byte
}

type TreeNode struct {
	Username string    //username
	UUID     uuid.UUID //uuid of invitation structs
	Children []*TreeNode
}

/* =====HELPER FUNCTIONS====== */

// generate deterministic salt
func genDetSalt(username, password string) []byte {
	input := username + password
	hash := userlib.Hash([]byte(input))
	return hash[:16]
}

// generate deterministic UUID
func genDetUUID(input string) (uuid.UUID, error) {
	hash := userlib.Hash([]byte(input))
	detUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return uuid.Nil, err
	}
	return detUUID, nil
}

func (node *TreeNode) AddChild(child *TreeNode) {
	node.Children = append(node.Children, child)
}

// find parent node in tree this is for developing invitation access tree
func (node *TreeNode) FindNode(value string) *TreeNode {
	if node.Username == value {
		return node
	}
	for _, child := range node.Children {
		found := child.FindNode(value)
		if found != nil {
			return found
		}
	}
	return nil
}

// adds a child to the node identified by the given username
func AddChildToNode(tree *TreeNode, parentUsername string, child *TreeNode) error {
	parentNode := tree.FindNode(parentUsername)
	if parentNode == nil {
		return errors.New("parent node not found")
	}
	parentNode.AddChild(child)
	return nil
}

// removes node with the specified value and all its children from the tree
func (n *TreeNode) pruneTree(username string) bool {
	// Check if the current node has children
	if n.Children == nil {
		return false
	}

	// Iterate over the children
	for i, child := range n.Children {
		if child.Username == username {
			// Remove the child node from the slice
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return true
		}

		// Recursively prune the subtree
		if child.pruneTree(username) {
			return true
		}
	}
	return false
}

// TraverseAndEncrypt traverses the tree and encrypts each UserStruct
func TraverseAndEncrypt(userdata *User, node *TreeNode, invitedata Invitation) error {
	if node == nil {
		return nil
	}

	//encrypt & sign invitation struct with the users public key and store
	recUserUUID, err := genDetUUID(node.Username)
	if err != nil {
		return errors.New("could not make deterministic UUID")
	}

	keySignName := append(recUserUUID[len(recUserUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	encKey, ok := userlib.KeystoreGet(keyString)
	if !ok {
		return errors.New("could not get enc key")
	}

	macKey := userdata.PrivateSignKey

	inviteBytes, err := json.Marshal(invitedata)
	if err != nil {
		return errors.New("could not convert invitation struct to bytes")
	}

	symEncKey := userlib.RandomBytes(16)

	encInvitationKey, err := userlib.PKEEnc(encKey, symEncKey)
	if err != nil {
		return errors.New("5")
	}

	encInvitation := userlib.SymEnc(symEncKey, userlib.RandomBytes(16), inviteBytes)
	encInvitation = append(encInvitationKey, encInvitation...)

	signature, err := userlib.DSSign(macKey, encInvitation)
	if err != nil {
		return errors.New("6")
	}

	storeInvitation := append(encInvitation, signature...)
	userlib.DatastoreSet(node.UUID, storeInvitation)

	// Traverse the children nodes
	for _, child := range node.Children {
		if err := TraverseAndEncrypt(userdata, child, invitedata); err != nil {
			return err
		}
	}
	return nil
}

func updateUserStruct(userdata *User, filename string) (ok bool) {
	//get decryption key
	var filedata File
	fileDecKey, ok := userdata.KeyTable[filename+"ENC"]
	if !ok {
		return false
	}

	//get verification key
	fileVerKey, ok := userdata.KeyTable[filename+"MAC"]
	if !ok {
		return false
	}

	fileUUID, ok := userdata.FileTable[filename]
	if !ok {
		return false
	}

	fileEncVal, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return false
	}

	HMAC := fileEncVal[len(fileEncVal)-64:]
	fileEnc := fileEncVal[:len(fileEncVal)-64]
	HMACVer, err := userlib.HMACEval(fileVerKey[:16], fileEnc)
	if err == nil {
		isEqual := userlib.HMACEqual(HMAC, HMACVer)
		if isEqual {
			fileDecVal := userlib.SymDec(fileDecKey[:16], fileEnc)

			err = json.Unmarshal(fileDecVal, &filedata)
			if err == nil {
				return true
			}

		}
	}

	inviteUUID, ok := userdata.InvitationTable[filename]
	if !ok {
		return false
	}

	//get invitation struct, and check validity
	inviteEncVal, ok := userlib.DatastoreGet(inviteUUID)
	if !ok {
		return false
	}

	decKey := userdata.PrivateEncKey

	var inviteData Invitation

	inviteDecValKey, err := userlib.PKEDec(decKey, inviteEncVal[:256])
	if err != nil {
		return false
	}
	//if verification successful, attempt to decrypt and return user struct
	inviteDecVal := userlib.SymDec(inviteDecValKey[:16], inviteEncVal[256:len(inviteEncVal)-256])
	err = json.Unmarshal(inviteDecVal, &inviteData)
	if err != nil {
		return false
	}

	userdata.FileTable[filename] = inviteData.FileUUID
	userdata.KeyTable[filename+"ENC"] = inviteData.FileEncKey
	userdata.KeyTable[filename+"MAC"] = inviteData.FileSignKey
	userdata.TreeTable[filename] = inviteData.TreeUUID
	userdata.TreeKeyTable[filename+"ENC"] = inviteData.TreeEncKey
	userdata.TreeKeyTable[filename+"MAC"] = inviteData.TreeSignKey

	fileVerKey, ok = userdata.KeyTable[filename+"MAC"]
	if !ok {
		return false
	}

	fileDecKey, ok = userdata.KeyTable[filename+"ENC"]
	if !ok {
		return false
	}

	fileUUID, ok = userdata.FileTable[filename]
	if !ok {
		return false
	}

	fileEncVal, ok = userlib.DatastoreGet(fileUUID)
	if !ok {
		return false
	}

	HMAC = fileEncVal[len(fileEncVal)-64:]
	fileEnc = fileEncVal[:len(fileEncVal)-64]
	HMACVer, err = userlib.HMACEval(fileVerKey[:16], fileEnc)
	if err == nil {
		isEqual := userlib.HMACEqual(HMAC, HMACVer)
		if isEqual {
			fileDecVal := userlib.SymDec(fileDecKey[:16], fileEnc)

			err = json.Unmarshal(fileDecVal, &filedata)
			if err == nil {
				return true
			} else {
				return false
			}

		} else {
			return false
		}
	} else {
		return false
	}
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata *User

	if username == "" {
		return nil, errors.New("Username length cannot be 0")
	}

	//generate deterministic UUID based on username
	userUUID, err := genDetUUID(username)
	if err != nil {
		return nil, err
	}

	if _, ok := userlib.DatastoreGet(userUUID); ok {
		return nil, errors.New("username is already taken")
	}

	//username + password as symmetric key used to encrypt/decrypt this user struct
	//our deterministic salt is generated from hashing our user + password, hashing ensures that
	//an attacker cannot gain information based on salt
	salt := genDetSalt(username, password)
	passwordBytes := []byte(password)
	encKey := userlib.Argon2Key(passwordBytes, salt, 16)

	//create encrytion/decryption & signature RSA keys
	publicEncKey, privateEncKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	privateSignKey, publicVerKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	//create the userdata struct
	userdata = &User{
		Username:        username,
		PasswordHash:    encKey,
		PrivateEncKey:   privateEncKey,
		PrivateSignKey:  privateSignKey,
		FileTable:       make(map[string]uuid.UUID),
		KeyTable:        make(map[string][]byte),
		TreeTable:       make(map[string]uuid.UUID),
		TreeKeyTable:    make(map[string][]byte),
		InvitationTable: make(map[string]uuid.UUID),
	}

	//store public keys. name will be hashed userUUID as a string + ENC for encryption key
	//and + Verify for verification key

	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	err = userlib.KeystoreSet(keyString, publicEncKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(keyString+"Verify", publicVerKey)
	if err != nil {
		return nil, err
	}

	//convert user struct to bytes, encrypt using encKey, add signature using privateSignKey, and add to DataStore
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	encUser := userlib.SymEnc(encKey, userlib.RandomBytes(16), userBytes)

	signature, err := userlib.DSSign(privateSignKey, encUser)
	if err != nil {
		return nil, err
	}

	storeData := append(encUser, signature...)
	userlib.DatastoreSet(userUUID, storeData)

	return userdata, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	//attempt to get username based on its UUID and see if it exists and get value if it does exist
	userUUID, err := genDetUUID(username)
	if err != nil {
		return nil, err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return nil, errors.New("username does not exist")
	}

	// Get decryption key
	salt := genDetSalt(username, password)
	passwordBytes := []byte(password)
	decKey := userlib.Argon2Key(passwordBytes, salt, 16)

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return nil, errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return nil, errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(decKey[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return nil, err
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var filedata *File

	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return errors.New("1")
	}

	fileUUID, ok := userdata.FileTable[filename]
	if ok {
		//attempt to decrypt file
		isRevoked := updateUserStruct(userdata, filename)
		if isRevoked == false {
			return errors.New("user has been revoked@@@@@@@@")
		}

		filePointerUUID := uuid.New()

		filePointerData := &FilePointer{
			Content: content,
		}

		//create FilePointer struct and encrypt and sign
		//encrypt file struct and store in dataStore
		filePointerBytes, err := json.Marshal(filePointerData)
		if err != nil {
			return errors.New("file pointer could not be converted to bytes")
		}

		encKey, ok := userdata.KeyTable[filename+"ENC"]
		if !ok {
			return errors.New("could not get key")
		}
		macKey, ok := userdata.KeyTable[filename+"MAC"]
		if !ok {
			return errors.New("could not get key")
		}

		encFilePointer := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), filePointerBytes)

		HMAC, err := userlib.HMACEval(macKey[:16], encFilePointer)
		if err != nil {
			return errors.New("file pointer could not signed")
		}
		storeDataFilePointer := append(encFilePointer, HMAC...)
		userlib.DatastoreSet(filePointerUUID, storeDataFilePointer)

		filedata = &File{
			FileUUID: fileUUID,
			FileList: []uuid.UUID{filePointerUUID},
		}

	} else {

		filePointerUUID := uuid.New()

		fileUUID = uuid.New()
		userdata.FileTable[filename] = fileUUID

		filePointerData := &FilePointer{
			Content: content,
		}

		//create encryption/mac keys & store in keyTable
		sourceKey := userlib.RandomBytes(16)

		encKey, err := userlib.HashKDF(sourceKey, []byte("ENC"))
		if err != nil {
			return errors.New("Could not hash encryption key")
		}

		macKey, err := userlib.HashKDF(sourceKey, []byte("MAC"))
		if err != nil {
			return errors.New("Could not hash mac key")
		}

		userdata.KeyTable[filename+"ENC"] = encKey[:16]
		userdata.KeyTable[filename+"MAC"] = macKey[:16]

		//create FilePointer struct and encrypt and sign
		//encrypt file struct and store in dataStore
		filePointerBytes, err := json.Marshal(filePointerData)
		if err != nil {
			return errors.New("Could not convert filePointer to bytes")
		}

		encFilePointer := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), filePointerBytes)

		HMAC, err := userlib.HMACEval(macKey[:16], encFilePointer)
		if err != nil {
			return errors.New("HMAC eval fail")
		}
		storeDataFilePointer := append(encFilePointer, HMAC...)
		userlib.DatastoreSet(filePointerUUID, storeDataFilePointer)

		//create File struct
		filedata = &File{
			FileUUID: fileUUID,
			FileList: []uuid.UUID{filePointerUUID},
		}

		treeUUID := uuid.New()

		sourceKeyTree := userlib.RandomBytes(16)

		treeEncKey, err := userlib.HashKDF(sourceKeyTree, []byte("ENC"))
		if err != nil {
			return errors.New("treeEncKey hash fail")
		}

		treeMacKey, err := userlib.HashKDF(sourceKeyTree, []byte("MAC"))
		if err != nil {
			return errors.New("treeMacKey hash fail")
		}

		userdata.TreeTable[filename] = treeUUID
		userdata.TreeKeyTable[filename+"ENC"] = treeEncKey[:16]
		userdata.TreeKeyTable[filename+"MAC"] = treeMacKey[:16]

		treeData := &TreeNode{
			Username: userdata.Username,
		}

		treeBytes, err := json.Marshal(treeData)
		if err != nil {
			return errors.New("tree marshal fail")
		}

		encTree := userlib.SymEnc(treeEncKey[:16], userlib.RandomBytes(16), treeBytes)

		HMAC, err = userlib.HMACEval(treeMacKey[:16], encTree)
		if err != nil {
			return errors.New("HMAC eval fail")
		}
		storeTree := append(encTree, HMAC...)
		userlib.DatastoreSet(treeUUID, storeTree)
	}

	//encrypt file struct and store in dataStore
	if filedata != nil {
		fileBytes, err := json.Marshal(filedata)
		if err != nil {
			return err
		}

		fileUUID, ok := userdata.FileTable[filename]
		if !ok {
			return errors.New("could not get fileUUID")
		}

		encKey, ok := userdata.KeyTable[filename+"ENC"]
		if !ok {
			return errors.New("could not get key")
		}
		macKey, ok := userdata.KeyTable[filename+"MAC"]
		if !ok {
			return errors.New("could not get key")
		}

		encFile := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), fileBytes)

		HMAC, err := userlib.HMACEval(macKey[:16], encFile)
		if err != nil {
			return err
		}
		storeDataFile := append(encFile, HMAC...)
		userlib.DatastoreSet(fileUUID, storeDataFile)

	}

	//update user struct
	userUUID, err = genDetUUID(userdata.Username)
	if err != nil {
		return err
	}

	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	encUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), userBytes)

	signature, err := userlib.DSSign(userdata.PrivateSignKey, encUser)
	if err != nil {
		return err
	}

	storeData := append(encUser, signature...)
	userlib.DatastoreSet(userUUID, storeData)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var filedata File

	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return errors.New("1")
	}

	//attempt to get file based on its UUID and see if it exists and get value if it does exist
	fileUUID, ok := userdata.FileTable[filename]
	if !ok {
		return errors.New("file not found in file table")
	}

	isRevoked := updateUserStruct(userdata, filename)
	if !isRevoked {
		return errors.New("user has been revoked")
	}

	//decrypt file struct, recreate file struct, and reencrypt and add to DataStore\
	//get decryption key
	fileDecKey, ok := userdata.KeyTable[filename+"ENC"]
	if !ok {
		return errors.New("could not get file key")
	}

	//get verification key
	fileVerKey, ok := userdata.KeyTable[filename+"MAC"]
	if !ok {
		return errors.New("could not get mac key")
	}

	fileEncVal, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("could not get file encrypted value")
	}

	HMAC := fileEncVal[len(fileEncVal)-64:]
	fileEnc := fileEncVal[:len(fileEncVal)-64]
	HMACVer, err := userlib.HMACEval(fileVerKey, fileEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for verification.")
	}
	isEqual := userlib.HMACEqual(HMAC, HMACVer)
	if isEqual != true {
		return errors.New("could not verify integrity of the file 1")
	}
	fileDecVal := userlib.SymDec(fileDecKey, fileEnc)

	_ = json.Unmarshal(fileDecVal, &filedata)

	filePointerUUID := uuid.New()

	filedata.FileList = append(filedata.FileList, []uuid.UUID{filePointerUUID}...)

	filePointerData := &FilePointer{
		Content: content,
	}

	filePointerBytes, err := json.Marshal(filePointerData)
	if err != nil {
		return errors.New("could not marshal filepointer")
	}

	encFilePointer := userlib.SymEnc(fileDecKey, userlib.RandomBytes(16), filePointerBytes)

	HMAC, err = userlib.HMACEval(fileVerKey, encFilePointer)
	if err != nil {
		return errors.New("could not hmac eval encfilepointer")
	}
	storeFilePointer := append(encFilePointer, HMAC...)
	userlib.DatastoreSet(filePointerUUID, storeFilePointer)

	//encrypt file struct and store in dataStore
	fileBytes, err := json.Marshal(filedata)
	if err != nil {
		return errors.New("could not marshal filedata")
	}

	encKey, ok := userdata.KeyTable[filename+"ENC"]
	if !ok {
		return errors.New("could not get key")
	}
	macKey, ok := userdata.KeyTable[filename+"MAC"]
	if !ok {
		return errors.New("could not get key")
	}

	encFile := userlib.SymEnc(encKey, userlib.RandomBytes(16), fileBytes)

	HMAC, err = userlib.HMACEval(macKey, encFile)
	if err != nil {
		return errors.New("could not hmac eval encFile")
	}
	storeDataFile := append(encFile, HMAC...)
	userlib.DatastoreSet(fileUUID, storeDataFile)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var filedata File

	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return nil, err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return nil, errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return nil, errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return nil, errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return nil, errors.New("1")
	}

	//attempt to get file based on its UUID and see if it exists and get value if it does exist
	fileUUID, ok := userdata.FileTable[filename]
	if !ok {
		return nil, errors.New("file not found in file table")
	}

	isRevoked := updateUserStruct(userdata, filename)
	if !isRevoked {
		return nil, errors.New("user has been revoked")
	}

	//get decryption key
	fileDecKey, ok := userdata.KeyTable[filename+"ENC"]
	if !ok {
		return nil, errors.New("could not get encryption key")
	}

	//get verification key
	fileVerKey, ok := userdata.KeyTable[filename+"MAC"]
	if !ok {
		return nil, errors.New("could not get mac key")
	}

	fileEncVal, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, err
	}

	HMAC := fileEncVal[len(fileEncVal)-64:]
	fileEnc := fileEncVal[:len(fileEncVal)-64]
	HMACVer, err := userlib.HMACEval(fileVerKey[:16], fileEnc)
	if err != nil {
		return nil, errors.New("An error occurred while generating HMAC for verification.")
	}
	isEqual := userlib.HMACEqual(HMAC, HMACVer)
	if isEqual != true {
		return nil, errors.New("could not verify integrity of the file 2")
	}
	fileDecVal := userlib.SymDec(fileDecKey[:16], fileEnc)

	_ = json.Unmarshal(fileDecVal, &filedata)

	var listUUID []uuid.UUID
	listUUID = filedata.FileList

	var combinedFileData []byte
	//traverse through list of UUIDS, decrypt each value, get contents, and append to combinedContents
	for _, fileUUID := range listUUID {
		fileEncVal, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return nil, err
		}

		HMAC := fileEncVal[len(fileEncVal)-64:]
		fileEnc = fileEncVal[:len(fileEncVal)-64]
		HMACVer, err := userlib.HMACEval(fileVerKey[:16], fileEnc)
		if err != nil {
			return nil, errors.New("An error occurred while generating HMAC for verification.")
		}
		isEqual := userlib.HMACEqual(HMAC, HMACVer)
		if isEqual != true {
			return nil, errors.New("could not verify integrity of the file 3")
		}
		fileDecVal = userlib.SymDec(fileDecKey[:16], fileEnc)

		var filePointer FilePointer
		_ = json.Unmarshal(fileDecVal, &filePointer)

		combinedFileData = append(combinedFileData, filePointer.Content...)
	}

	return combinedFileData, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return uuid.Nil, errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return uuid.Nil, errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return uuid.Nil, errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return uuid.Nil, errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return uuid.Nil, errors.New("1")
	}

	//check if file exists
	_, ok = userdata.FileTable[filename]
	if !ok {
		return uuid.Nil, errors.New("file not found in file table")
	}

	//check if recipientUser exists & need some way of verifying recipientUser is who it claims to be
	recUserUUID, err := genDetUUID(recipientUsername)
	if err != nil {
		return uuid.Nil, errors.New("2")
	}
	if _, ok := userlib.DatastoreGet(recUserUUID); !ok {
		return uuid.Nil, errors.New("user does not exist")
	}

	//create invitation struct
	invitedata := &Invitation{
		FileUUID:    userdata.FileTable[filename],
		FileEncKey:  userdata.KeyTable[filename+"ENC"],
		FileSignKey: userdata.KeyTable[filename+"MAC"],
		TreeUUID:    userdata.TreeTable[filename],
		TreeEncKey:  userdata.TreeKeyTable[filename+"ENC"],
		TreeSignKey: userdata.TreeKeyTable[filename+"MAC"],
	}

	//use recipient Users public keys to encrypt and sign invitation struct
	inviteUUID := uuid.New()
	inviteBytes, err := json.Marshal(invitedata)
	if err != nil {
		return uuid.Nil, errors.New("3")
	}

	keySignName = append(recUserUUID[len(recUserUUID)-13:], []byte("ENC")...)
	keyString = string(keySignName)
	encKey, ok := userlib.KeystoreGet(keyString)
	if !ok {
		return uuid.Nil, errors.New("4")
	}

	macKey := userdata.PrivateSignKey

	//use hybrid encryption
	symEncKey := userlib.RandomBytes(16)

	encInvitationKey, err := userlib.PKEEnc(encKey, symEncKey)
	if err != nil {
		return uuid.Nil, errors.New("5")
	}

	encInvitation := userlib.SymEnc(symEncKey, userlib.RandomBytes(16), inviteBytes)
	encInvitation = append(encInvitationKey, encInvitation...)

	signature, err := userlib.DSSign(macKey, encInvitation)
	if err != nil {
		return uuid.Nil, errors.New("6")
	}

	storeInvitation := append(encInvitation, signature...)
	userlib.DatastoreSet(inviteUUID, storeInvitation)

	//update user struct
	userUUID, err = genDetUUID(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}

	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return uuid.Nil, err
	}

	encUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), userBytes)

	signature, err = userlib.DSSign(userdata.PrivateSignKey, encUser)
	if err != nil {
		return uuid.Nil, err
	}

	storeData := append(encUser, signature...)
	userlib.DatastoreSet(userUUID, storeData)

	return inviteUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//check if user already has a file of that filename
	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return errors.New("1")
	}

	_, ok = userdata.FileTable[filename]
	if ok {
		return errors.New("file already exists")
	}

	userdata.InvitationTable[filename] = invitationPtr

	//get invitation struct, and check validity
	inviteEncVal, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Could not get invitation struct form DataStore")
	}

	userUUID, err = genDetUUID(senderUsername)
	if err != nil {
		return err
	}

	decKey := userdata.PrivateEncKey
	keySignName = append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString = string(keySignName)
	DSVerifyKey, ok = userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return errors.New("keystoreGet failed")
	}

	var inviteData Invitation

	err = userlib.DSVerify(DSVerifyKey, inviteEncVal[:(len(inviteEncVal)-256)], inviteEncVal[(len(inviteEncVal)-256):])
	if err != nil {
		fmt.Println("Verification of invitation signature has failed")
	} else {
		//hybrid decryption
		inviteDecValKey, err := userlib.PKEDec(decKey, inviteEncVal[:256])
		if err != nil {
			return err
		}
		//if verification successful, attempt to decrypt and return user struct
		inviteDecVal := userlib.SymDec(inviteDecValKey[:16], inviteEncVal[256:len(inviteEncVal)-256])
		_ = json.Unmarshal(inviteDecVal, &inviteData)
	}

	//add the new user to the inivitation tree and update its keyTable and fileTable
	userdata.FileTable[filename] = inviteData.FileUUID
	userdata.KeyTable[filename+"ENC"] = inviteData.FileEncKey
	userdata.KeyTable[filename+"MAC"] = inviteData.FileSignKey
	userdata.TreeTable[filename] = inviteData.TreeUUID
	userdata.TreeKeyTable[filename+"ENC"] = inviteData.TreeEncKey
	userdata.TreeKeyTable[filename+"MAC"] = inviteData.TreeSignKey

	//get tree at the treeUUID
	treeEncVal, ok := userlib.DatastoreGet(inviteData.TreeUUID)
	if !ok {
		return errors.New("Could not get tree struct form DataStore")
	}

	//decrypt and verifyvalue at treeUUID to get the tree
	HMAC := treeEncVal[len(treeEncVal)-64:]
	treeEnc := treeEncVal[:len(treeEncVal)-64]
	HMACVer, err := userlib.HMACEval(inviteData.TreeSignKey, treeEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for verification.")
	}
	isEqual := userlib.HMACEqual(HMAC, HMACVer)
	if isEqual != true {
		return errors.New("could not verify integrity of the file")
	}
	treeDecVal := userlib.SymDec(inviteData.TreeEncKey, treeEnc)

	var treeData TreeNode
	_ = json.Unmarshal(treeDecVal, &treeData)

	//update treeUUID corresponding value by adding yourself to the tree
	user := &TreeNode{Username: userdata.Username, UUID: invitationPtr}
	AddChildToNode(&treeData, senderUsername, user)

	//reencrypt treeData and update Datatore
	treeBytes, err := json.Marshal(treeData)
	if err != nil {
		return err
	}

	encTree := userlib.SymEnc(inviteData.TreeEncKey, userlib.RandomBytes(16), treeBytes)

	HMAC, err = userlib.HMACEval(inviteData.TreeSignKey, encTree)
	if err != nil {
		return err
	}
	storeTree := append(encTree, HMAC...)
	userlib.DatastoreSet(inviteData.TreeUUID, storeTree)

	//update user struct
	userUUID, err = genDetUUID(userdata.Username)
	if err != nil {
		return err
	}

	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	encUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), userBytes)

	signature, err := userlib.DSSign(userdata.PrivateSignKey, encUser)
	if err != nil {
		return err
	}

	storeData := append(encUser, signature...)
	userlib.DatastoreSet(userUUID, storeData)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//reencrypt revoked users
	//get user encrypted
	userUUID, err := genDetUUID(userdata.Username)
	if err != nil {
		return err
	}
	if _, ok := userlib.DatastoreGet(userUUID); !ok {
		return errors.New("username does not exist")
	}

	// Get verification key & value at userUUID
	keySignName := append(userUUID[len(userUUID)-13:], []byte("ENC")...)
	keyString := string(keySignName)
	DSVerifyKey, ok := userlib.KeystoreGet(keyString + "Verify")
	if !ok {
		return errors.New("keystoreGet failed")
	}

	// Get data and check for tampering
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("DatastoreGet failed")
	}

	err = userlib.DSVerify(DSVerifyKey, data[:(len(data)-256)], data[(len(data)-256):])
	if err != nil {
		return errors.New("Verification of signature has failed")
	}

	// If verification successful, attempt to decrypt and return user struct
	userDecVal := userlib.SymDec(userdata.PasswordHash[:16], data[:len(data)-256])
	if err := json.Unmarshal(userDecVal, &userdata); err != nil {
		return errors.New("1")
	}

	//prune the tree
	fileUUID, ok := userdata.TreeTable[filename]
	if !ok {
		return errors.New("could not get uuid")
	}

	tUUID, ok := userdata.TreeTable[filename]
	if !ok {
		return errors.New("could not get uuid")
	}
	treeEncVal, ok := userlib.DatastoreGet(tUUID)
	if !ok {
		return errors.New("could not get uuid")
	}

	//decrypt and verify value at treeUUID to get the tree
	treeEncKey := userdata.TreeKeyTable[filename+"ENC"]
	treeVerKey := userdata.TreeKeyTable[filename+"MAC"]

	HMAC := treeEncVal[len(treeEncVal)-64:]
	treeEnc := treeEncVal[:len(treeEncVal)-64]
	HMACVer, err := userlib.HMACEval(treeVerKey, treeEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for verification.")
	}
	isEqual := userlib.HMACEqual(HMAC, HMACVer)
	if isEqual != true {
		return errors.New("could not verify integrity of the file")
	}
	treeDecVal := userlib.SymDec(treeEncKey[:16], treeEnc)

	var treeData TreeNode
	_ = json.Unmarshal(treeDecVal, &treeData)

	treeData.pruneTree(recipientUsername)

	//create new symmetric keys for the file struct as well as the tree struct
	filesourceKey := userlib.RandomBytes(16)

	fileEncKey, err := userlib.HashKDF(filesourceKey, []byte("ENC"))
	if err != nil {
		return err
	}

	fileMacKey, err := userlib.HashKDF(filesourceKey, []byte("MAC"))
	if err != nil {
		return err
	}

	treesourceKey := userlib.RandomBytes(16)

	treeEncKey, err = userlib.HashKDF(treesourceKey, []byte("ENC"))
	if err != nil {
		return err
	}

	treeMacKey, err := userlib.HashKDF(treesourceKey, []byte("MAC"))
	if err != nil {
		return err
	}

	//make a new invite struct with the new keys used to decrypt the file
	invitedata := &Invitation{
		FileUUID:    userdata.FileTable[filename],
		FileEncKey:  fileEncKey,
		FileSignKey: fileMacKey,
		TreeUUID:    userdata.TreeTable[filename],
		TreeEncKey:  treeEncKey,
		TreeSignKey: treeMacKey,
	}

	//decrypt file
	fUUID, ok := userdata.FileTable[filename]
	if !ok {
		return errors.New("could not get file")
	}
	fileEncVal, ok := userlib.DatastoreGet(fUUID)
	if !ok {
		return errors.New("could not get file UUID")
	}

	HMAC = fileEncVal[len(fileEncVal)-64:]
	fileEnc := fileEncVal[:len(fileEncVal)-64]

	mKey, ok := userdata.KeyTable[filename+"MAC"]
	if !ok {
		return errors.New("could not get key")
	}
	eKey, ok := userdata.KeyTable[filename+"ENC"]
	if !ok {
		return errors.New("could not get key")
	}

	HMACVer, err = userlib.HMACEval(mKey[:16], fileEnc)
	if err != nil {
		return errors.New("An error occurred while generating HMAC for verification.")
	}
	isEqual = userlib.HMACEqual(HMAC, HMACVer)
	if isEqual != true {
		return errors.New("could not verify integrity of the file")
	}
	fileDecVal := userlib.SymDec(eKey[:16], fileEnc)

	var fileData File
	_ = json.Unmarshal(fileDecVal, &fileData)

	//re-encrypt file and tree with new keys and add new key to keyTable
	fileBytes, err := json.Marshal(fileData)
	if err != nil {
		return err
	}

	encFile := userlib.SymEnc(fileEncKey[:16], userlib.RandomBytes(16), fileBytes)

	HMAC, err = userlib.HMACEval(fileMacKey[:16], encFile)
	if err != nil {
		return err
	}
	storeDataFile := append(encFile, HMAC...)

	userlib.DatastoreSet(fUUID, storeDataFile)

	userdata.KeyTable[filename+"ENC"] = fileEncKey[:16]
	userdata.KeyTable[filename+"MAC"] = fileMacKey[:16]

	treeBytes, err := json.Marshal(treeData)
	if err != nil {
		return err
	}

	encTree := userlib.SymEnc(treeEncKey[:16], userlib.RandomBytes(16), treeBytes)

	HMAC, err = userlib.HMACEval(treeMacKey[:16], encTree)
	if err != nil {
		return err
	}
	storeTree := append(encTree, HMAC...)
	userlib.DatastoreSet(fileUUID, storeTree)

	userdata.TreeKeyTable[filename+"ENC"] = treeEncKey[:16]
	userdata.TreeKeyTable[filename+"MAC"] = treeMacKey[:16]

	//traverse through the tree, we reencrypt and replace the old value at the invite UUID with the newly encrypted invite
	//we do this with the users public keys in the tree
	TraverseAndEncrypt(userdata, &treeData, *invitedata)

	var listUUID []uuid.UUID
	listUUID = fileData.FileList

	//decrypt each filepointer and reecnrypt with new key
	//traverse through list of UUIDS and reecnrypt
	for _, fileUUID := range listUUID {
		//get decryption key
		fileDecKey := eKey

		//get verification key
		fileVerKey := mKey

		fileEncVal, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return err
		}

		HMAC := fileEncVal[len(fileEncVal)-64:]
		fileEnc := fileEncVal[:len(fileEncVal)-64]
		HMACVer, err := userlib.HMACEval(fileVerKey, fileEnc)
		if err != nil {
			return errors.New("An error occurred while generating HMAC for verification.")
		}
		isEqual := userlib.HMACEqual(HMAC, HMACVer)
		if isEqual != true {
			return errors.New("could not verify integrity of the file 2")
		}
		fileDecVal := userlib.SymDec(fileDecKey, fileEnc)
		//POSSIBLE BUG FIGURE OUT IF YOU NEED [:16]

		encFilePointer := userlib.SymEnc(fileEncKey[:16], userlib.RandomBytes(16), fileDecVal)

		HMAC, err = userlib.HMACEval(fileMacKey[:16], encFilePointer)
		if err != nil {
			return errors.New("file pointer could not signed")
		}
		storeDataFilePointer := append(encFilePointer, HMAC...)
		userlib.DatastoreSet(fileUUID, storeDataFilePointer)
	}

	//update user struct
	userUUID, err = genDetUUID(userdata.Username)
	if err != nil {
		return err
	}

	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	encUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), userBytes)

	signature, err := userlib.DSSign(userdata.PrivateSignKey, encUser)
	if err != nil {
		return err
	}

	storeData := append(encUser, signature...)
	userlib.DatastoreSet(userUUID, storeData)

	return nil
}
