package walletapi

import (
	"encoding/hex"
	"github.com/33cn/chain33/common/address"
	"github.com/33cn/chain33/common/crypto"
	chainTypes "github.com/33cn/chain33/types"
	chainUtil "github.com/33cn/chain33/util"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"math/rand"
	"strings"
)

const (
	SECP256K1 = 1

	minFeeRate = 100000
	noFeeRate  = -1
)

// Config
type Config struct {
	Chain   Chain
	Encrypt Encrypt
}

type Chain struct {
	FeePrikey string
	FeeAddr   string
	Title     string
	BaseExec  string `json:",default=none"`
}

type Encrypt struct {
	SignType int32 `json:",default=1"` // Invalid=0,SECP256K1=1,ED25519=2,SM2=3
}

type TxInfo struct {
	Exec    string
	Payload []byte
	FeeRate int64
	Prikey  string
}

type ChainClient struct {
	cfg    *Config
	FeePri crypto.PrivKey
}

func NewChainClient(c *Config) (*ChainClient, error) {
	if c == nil {
		return nil, errors.New("ChainClient: illegal ChainClient configure")
	}
	if c.Encrypt.SignType == 0 {
		c.Encrypt.SignType = SECP256K1
	}
	c.Chain.BaseExec = c.Chain.Title + chainTypes.NoneX
	var pri crypto.PrivKey
	if c.Chain.FeePrikey != "" {
		pri = chainUtil.HexToPrivkey(c.Chain.FeePrikey)
	}
	return &ChainClient{cfg: c, FeePri: pri}, nil
}

// CreateTx
func (c *ChainClient) createTx(t *TxInfo) *chainTypes.Transaction {
	tx := &chainTypes.Transaction{
		Execer:  []byte(t.Exec),
		Payload: t.Payload,
		Nonce:   rand.Int63(),
		To:      address.ExecAddress(t.Exec),
	}
	if t.FeeRate != noFeeRate {
		if t.FeeRate == 0 {
			t.FeeRate = minFeeRate
		}
		tx.SetRealFee(t.FeeRate)
	}

	return tx
}

func (c *ChainClient) createSignTx(prikey string, tx *chainTypes.Transaction) *chainTypes.Transaction {
	priv := chainUtil.HexToPrivkey(prikey)
	tx.Sign(c.cfg.Encrypt.SignType, priv)
	return tx
}

func (c *ChainClient) createBaseTx(exec string) *chainTypes.Transaction {
	tx := &chainTypes.Transaction{
		Execer: []byte(exec),
		Nonce:  rand.Int63(),
		To:     address.ExecAddress(exec),
	}
	return tx
}

func (c *ChainClient) createSignTxGroup(prikey string, tx2 *chainTypes.Transaction) (*chainTypes.Transaction, error) {
	var txs []*chainTypes.Transaction
	tx1 := c.createBaseTx(c.cfg.Chain.BaseExec)
	txs = append(txs, tx1, tx2)
	txGroup, err := chainTypes.CreateTxGroup(txs, minFeeRate)
	if err != nil {
		return nil, err
	}
	err = txGroup.SignN(0, c.cfg.Encrypt.SignType, c.FeePri)
	if err != nil {
		return nil, err
	}
	priv := chainUtil.HexToPrivkey(prikey)
	err = txGroup.SignN(1, c.cfg.Encrypt.SignType, priv)
	if err != nil {
		return nil, err
	}
	return txGroup.Tx(), nil
}

func (c *ChainClient) SignTransaction(txHex string, privKey string) (string, error) {
	txHex = strings.Replace(txHex, "0x", "", -1)
	txBuf, err := hex.DecodeString(txHex)
	if err != nil {
		return "", err
	}
	var tx chainTypes.Transaction
	err = proto.Unmarshal(txBuf, &tx)
	if err != nil {
		return "", err
	}

	txGroup := c.createSignTx(privKey, &tx)
	rltBuf, err := proto.Marshal(txGroup)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rltBuf), nil
}

func (c *ChainClient) SignTransactionGroup(index int32, txHex string, privKey string) (string, error) {
	txHex = strings.Replace(txHex, "0x", "", -1)
	txBuf, err := hex.DecodeString(txHex)
	if err != nil {
		return "", err
	}
	var tx chainTypes.Transaction
	err = proto.Unmarshal(txBuf, &tx)
	if err != nil {
		return "", err
	}

	txs, err := tx.GetTxGroup()
	if err != nil {
		return "", err
	}

	priv := chainUtil.HexToPrivkey(privKey)
	if index == 0 {
		for i := range txs.Txs {
			err = txs.SignN(i, c.cfg.Encrypt.SignType, priv)
			if err != nil {
				return "", err
			}
		}
	} else {
		index--
		err = txs.SignN(int(index), c.cfg.Encrypt.SignType, priv)
		if err != nil {
			return "", err
		}
	}

	rltBuf, err := proto.Marshal(txs.Tx())
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rltBuf), nil
}

func (c *ChainClient) SignNoBalanceTransaction(txHex string, privKey string) (string, error) {
	txHex = strings.Replace(txHex, "0x", "", -1)
	txBuf, err := hex.DecodeString(txHex)
	if err != nil {
		return "", err
	}
	var tx chainTypes.Transaction
	err = proto.Unmarshal(txBuf, &tx)
	if err != nil {
		return "", err
	}

	txGroup, err := c.createSignTxGroup(privKey, &tx)
	if err != nil {
		return "", err
	}

	rltBuf, err := proto.Marshal(txGroup)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rltBuf), nil
}
