//go:build js && wasm
// +build js,wasm

package main

import (
	"errors"

	"fmt"
	"os"
	"strconv"

	"github.com/0chain/gosdk/core/client"
	"github.com/0chain/gosdk/core/zcncrypto"
	"github.com/0chain/gosdk/wasmsdk/jsbridge"
)

func setWallet(clientID, clientKey, peerPublicKey, publicKey, privateKey, mnemonic string, isSplit bool) error {
	if mnemonic == "" && !isSplit {
		return errors.New("mnemonic is required")
	}
	mode := os.Getenv("MODE")
	fmt.Println("gosdk setWallet, mode:", mode, "is split:", isSplit)
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
	fmt.Println("set Wallet, is split:", isSplit)
	client.SetWallet(*w)

	zboxApiClient.SetWallet(clientID, privateKey, clientKey)
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

func setWalletMode(mode bool) {
	client.SetWalletMode(mode)

	fmt.Println("gosdk setWalletMode: ", "is split:", mode)
}
