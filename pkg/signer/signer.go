package signer

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"math/big"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/core/types"
)

type Signer interface {
	SignTx(transaction *types.Transaction, chainID *big.Int) (*types.Transaction, error)
	NewHDWallet(params *chaincfg.Params) error
	DeriveFromParent(parent *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error)
	defaultBip44Path() []uint32
	deriveCustomBip44Path(coinType, account, change, index uint32) []uint32
	GetSharedKey(their ecdsa.PublicKey) [32]byte
	GenNonce() []byte
	EncryptAndGetHash(key [32]byte, nonce []byte, message []byte) ([32]byte, []byte, error)
	DecryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) (string, error)
	getCipherMode(key []byte) (cipher.AEAD, error)
	VerifySignature(publicKey ecdsa.PublicKey, signature, messageHash []byte) bool
	Sign(hash [32]byte) ([]byte, error)
	GetPublicKey() *ecdsa.PublicKey
}

type signer struct {
	Wallet *hdWallet
}

func New(params *chaincfg.Params) (Signer, error) {
	newSigner := &signer{}

	err := newSigner.NewHDWallet(params)
	if err != nil {
		return nil, err
	}

	return newSigner, nil
}
