//go:build js && wasm
// +build js,wasm

package main

import (
	"errors"
	"github.com/0chain/common/core/logging"

	"log"
	"os"
	"strconv"

	"github.com/0chain/gosdk/core/client"
	"github.com/0chain/gosdk/core/zcncrypto"
	"github.com/0chain/gosdk/wasmsdk/jsbridge"
)

func setWallet(clientID, clientKey, peerPublicKey, publicKey, privateKey, mnemonic string, isSplit bool) error {
	log.Println("Set Wallet called")
	logging.Logger.Info("2 Set Wallet called")
	log.Println("ClientID : ", clientID)
	log.Println("ClientKey : ", clientKey)
	log.Println("PeerPublicKey : ", peerPublicKey)
	log.Println("PublicKey : ", publicKey)
	log.Println("PrivateKey : ", privateKey)
	log.Println("Mnemonic : ", mnemonic)
	log.Println("IsSplit : ", isSplit)

	if mnemonic == "" && !isSplit {
		return errors.New("mnemonic is required")
	}

	log.Println("Here 1")

	mode := os.Getenv("MODE")
	log.Println("gosdk setWallet, mode:", mode, "is split:", isSplit)
	keys := []zcncrypto.KeyPair{
		{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
	}

	w := &zcncrypto.Wallet{
		ClientID:      clientID,
		ClientKey:     clientKey,
		PeerPublicKey: peerPublicKey,
		Mnemonic:      mnemonic,
		Keys:          keys,
		IsSplit:       isSplit,
	}
	log.Println("set Wallet, is split:", isSplit)
	client.SetWallet(*w)
	log.Println("Here 2")
	log.Println("Wallet ID", client.ClientID())

	zboxApiClient.SetWallet(clientID, privateKey, publicKey)
	if mode == "" { // main thread, need to notify the web worker to update wallet
		// notify the web worker to update wallet
		if err := jsbridge.PostMessageToAllWorkers(jsbridge.MsgTypeUpdateWallet, map[string]string{
			"client_id":       clientID,
			"client_key":      clientKey,
			"peer_public_key": peerPublicKey,
			"public_key":      publicKey,
			"private_key":     privateKey,
			"mnemonic":        mnemonic,
			"is_split":        strconv.FormatBool(isSplit),
		}); err != nil {
			return err
		}
	}

	return nil
}
