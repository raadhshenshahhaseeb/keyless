package signer

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

type hdWallet struct {
	MasterKey      *hdkeychain.ExtendedKey
	EcdsaKeyPair   *ECDSAKeyPair
	NextChildIndex uint32
	Paths          map[string]string
}

func (s *signer) NewHDWallet(params *chaincfg.Params) error {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return err
	}

	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return err
	}

	s.Wallet = &hdWallet{
		MasterKey:      masterKey,
		NextChildIndex: 0,
		Paths:          make(map[string]string),
	}

	return nil
}

func (s *signer) DeriveFromParent(parent *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
	parent.Depth()
	return parent, nil
}

func (s *signer) defaultBip44Path() []uint32 {
	return []uint32{
		44 + hdkeychain.HardenedKeyStart,
		0 + hdkeychain.HardenedKeyStart,
		0 + hdkeychain.HardenedKeyStart,
		0,
		0,
	}
}

func (s *signer) deriveCustomBip44Path(coinType, account, change, index uint32) []uint32 {
	return []uint32{
		44 + hdkeychain.HardenedKeyStart, // BIP44 proposal
		coinType + hdkeychain.HardenedKeyStart,
		account + hdkeychain.HardenedKeyStart,
		change,
		index,
	}
}
