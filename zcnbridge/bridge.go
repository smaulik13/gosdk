package zcnbridge

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/0chain/gosdk/core/zcncrypto"
	"github.com/0chain/gosdk/zcnbridge/chain"

	comerr "github.com/0chain/gosdk/zcnbridge/errors"
	"github.com/0chain/gosdk/zcnbridge/ethereum"
	binding "github.com/0chain/gosdk/zcnbridge/ethereum/bridge"
	"github.com/0chain/gosdk/zcnbridge/ethereum/erc20"
	"github.com/0chain/gosdk/zcnbridge/log"
	"github.com/0chain/gosdk/zcnbridge/transaction"
	"github.com/0chain/gosdk/zcnbridge/wallet"
	"github.com/0chain/gosdk/zcnbridge/zcnsc"
	"github.com/0chain/gosdk/zcncore"
	eth "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type (
	Wei int64
)

var (
	DefaultClientIDEncoder = func(id string) []byte {
		return []byte(id)
	}
)

// IncreaseBurnerAllowance Increases allowance for bridge contract address to transfer
// WZCN tokens on behalf of the token owner to the Burn TokenPool
// During the burn the script transfers amount from token owner to the bridge burn token pool
// Example: owner wants to burn some amount.
// The contract will transfer some amount from owner address to the pool.
// So the owner must call IncreaseAllowance of the WZCN token with 2 parameters:
// spender address which is the bridge contract and amount to be burned (transferred)
//nolint:funlen
// ERC20 signature: "increaseAllowance(address,uint256)"
func (b *Bridge) IncreaseBurnerAllowance(ctx context.Context, amountWei Wei) (*types.Transaction, error) {
	etherClient, err := b.CreateEthClient()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create etherClient")
	}

	// 1. Data Parameter (spender)
	spenderAddress := common.HexToAddress(b.BridgeAddress)

	// 2. Data Parameter (amount)
	amount := big.NewInt(int64(amountWei))

	ethWallet := b.GetEthereumWallet()
	ownerAddress, _, privKey := ethWallet.Address, ethWallet.PublicKey, ethWallet.PrivateKey
	if err != nil {
		return nil, errors.Wrap(err, "failed to read private key and ownerAddress")
	}

	tokenAddress := common.HexToAddress(b.WzcnAddress)
	fromAddress := ownerAddress

	abi, err := erc20.ERC20MetaData.GetAbi()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get erc20 abi")
	}

	pack, err := abi.Pack("increaseAllowance", spenderAddress, amount)
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack arguments")
	}

	gasLimitUnits, err := etherClient.EstimateGas(ctx, eth.CallMsg{
		To:   &tokenAddress,
		From: fromAddress,
		Data: pack,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to estimate gas limit")
	}

	gasLimitUnits = addPercents(gasLimitUnits, 10).Uint64()
	chainID, err := etherClient.ChainID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get chain ID")
	}

	transactOpts := b.CreateSignedTransaction(chainID, etherClient, ownerAddress, privKey, gasLimitUnits)

	wzcnTokenInstance, err := erc20.NewERC20(tokenAddress, etherClient)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize WZCN-ERC20 instance")
	}

	log.Logger.Info(
		"IncreaseAllowance",
		zap.String("token", tokenAddress.String()),
		zap.String("spender", spenderAddress.String()),
		zap.Int64("amount", amount.Int64()),
	)

	tran, err := wzcnTokenInstance.IncreaseAllowance(transactOpts, spenderAddress, amount)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send `IncreaseAllowance` transaction")
	}

	return tran, nil
}

func GetTransactionStatus(hash string) (int, error) {
	_, err := zcncore.GetEthClient()
	if err != nil {
		return -1, err // TODO: Notify that EthClient failed so doesn't make sense to make retries
	}

	return zcncore.CheckEthHashStatus(hash), nil
}

func ConfirmEthereumTransaction(hash string, times int, duration time.Duration) (int, error) {
	var (
		res = 0
		err error
	)

	if hash == "" {
		return -1, errors.New("transaction hash should not be empty")
	}

	for i := 0; i < times; i++ {
		res, err = GetTransactionStatus(hash)
		if err != nil {
			return -1, err
		}
		if res == 1 || res == 0 {
			break
		}
		log.Logger.Info(fmt.Sprintf("try # %d", i))
		time.Sleep(duration)
	}
	return res, nil
}

func (b *Bridge) VerifyZCNTransaction(ctx context.Context, hash string) (*transaction.Transaction, error) {
	return transaction.VerifyTransaction(ctx, hash, b.ID(), b.PublicKey())
}

func (b *Bridge) TestSign(hash string) (string, error) {
	scheme := chain.GetServerChain().SignatureScheme
	signScheme := zcncrypto.NewSignatureScheme(scheme)
	if signScheme != nil {
		err := signScheme.SetPrivateKey(b.PrivateKey())
		if err != nil {
			return "", err
		}
		return signScheme.Sign(hash)
	}
	return "", comerr.NewError("invalid_signature_scheme", "Invalid signature scheme. Please check configuration")
}

// MintWZCN Mint ZCN tokens on behalf of the 0ZCN client
// payload: received from authorizers
func (b *Bridge) MintWZCN(ctx context.Context, payload *ethereum.MintPayload) (*types.Transaction, error) {
	if DefaultClientIDEncoder == nil {
		return nil, errors.New("DefaultClientIDEncoder must be setup")
	}

	// 1. Data Parameter (amount to burn)
	amount := new(big.Int)
	amount.SetInt64(payload.Amount) // wei

	// 2. Data Parameter (zcnTxd string as []byte)
	zcnTxd := DefaultClientIDEncoder(payload.ZCNTxnID)

	// 3. Nonce Parameter
	nonce := new(big.Int)
	nonce.SetInt64(payload.Nonce)

	// 4. Signature
	// For requirements from ERC20 authorizer, the signature length must be 65
	var sb strings.Builder
	for _, signature := range payload.Signatures {
		sb.WriteString(signature.Signature)
	}
	sigs := []byte(sb.String())

	bridgeInstance, transactOpts, err := b.prepareBridge(ctx, "mint", amount, zcnTxd, nonce, sigs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare bridge")
	}

	tran, err := bridgeInstance.Mint(transactOpts, amount, zcnTxd, nonce, sigs)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to execute MintWZCN transaction, ClientID = %s, amount = %s, ZCN TrxID = %s",
			b.ID(),
			amount,
			zcnTxd,
		)
	}

	return tran, err
}

// BurnWZCN Burns WZCN tokens on behalf of the 0ZCN client
// amountTokens - ZCN tokens
// clientID - 0ZCN client
// ERC20 signature: "burn(uint256,bytes)"
func (b *Bridge) BurnWZCN(ctx context.Context, amountTokens int64) (*types.Transaction, error) {
	if DefaultClientIDEncoder == nil {
		return nil, errors.New("DefaultClientIDEncoder must be setup")
	}

	// 1. Data Parameter (amount to burn)
	clientID := DefaultClientIDEncoder(b.ID())

	// 2. Data Parameter (signature)
	amount := new(big.Int)
	amount.SetInt64(amountTokens)

	bridgeInstance, transactOpts, err := b.prepareBridge(ctx, "burn", amount, clientID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare bridge")
	}

	tran, err := bridgeInstance.Burn(transactOpts, amount, clientID)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to execute BurnZCN transaction to ClientID = %s with amount = %s",
			b.ID(),
			amount,
		)
	}

	return tran, err
}

func (b *Bridge) MintZCN(ctx context.Context, payload *zcnsc.MintPayload) (*transaction.Transaction, error) {
	trx, err := transaction.NewTransactionEntity(b.ID(), b.PublicKey())
	if err != nil {
		log.Logger.Fatal("failed to create new transaction", zap.Error(err))
	}

	hash, err := trx.ExecuteSmartContract(
		ctx,
		wallet.ZCNSCSmartContractAddress,
		wallet.MintFunc,
		string(payload.Encode()),
		0,
	)

	if err != nil {
		return trx, errors.Wrap(err, fmt.Sprintf("failed to execute smart contract, hash = %s", hash))
	}

	return trx, nil
}

func (b *Bridge) BurnZCN(ctx context.Context, amount int64) (*transaction.Transaction, error) {
	address := b.GetEthereumAddress()

	payload := zcnsc.BurnPayload{
		Nonce:           b.IncrementNonce(),
		EthereumAddress: address.String(), // TODO: this should be receiver address not the bridge
	}

	trx, err := transaction.NewTransactionEntity(b.ID(), b.PublicKey())
	if err != nil {
		log.Logger.Fatal("failed to create new transaction", zap.Error(err))
	}

	trx.Value = amount

	hash, err := trx.ExecuteSmartContract(
		ctx,
		wallet.ZCNSCSmartContractAddress,
		wallet.BurnFunc,
		string(payload.Encode()),
		amount,
	)

	if err != nil {
		return trx, errors.Wrap(err, fmt.Sprintf("failed to execute smart contract, hash = %s", hash))
	}

	return trx, nil
}

func addPercents(gasLimitUnits uint64, percents int) *big.Int {
	gasLimitBig := big.NewInt(int64(gasLimitUnits))
	factorBig := big.NewInt(int64(percents))
	deltaBig := gasLimitBig.Div(gasLimitBig, factorBig)

	origin := big.NewInt(int64(gasLimitUnits))
	gasLimitBig = origin.Add(origin, deltaBig)

	return gasLimitBig
}

func (b *Bridge) prepareBridge(ctx context.Context, method string, params ...interface{}) (*binding.Bridge, *bind.TransactOpts, error) {
	etherClient, err := b.CreateEthClient()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create etherClient")
	}

	// To
	bridgeAddress := common.HexToAddress(b.BridgeAddress)

	// cmd Ethereum wallet
	ethereumWallet := b.GetEthereumWallet()

	// Get ABI of the contract
	abi, err := binding.BridgeMetaData.GetAbi()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get ABI")
	}

	// Pack the method argument
	pack, err := abi.Pack(method, params...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to pack arguments")
	}

	// Gas limits in units
	gasLimitUnits, err := etherClient.EstimateGas(ctx, eth.CallMsg{
		To:   &bridgeAddress,
		From: ethereumWallet.Address,
		Data: pack,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to estimate gas")
	}

	gasLimitUnits = addPercents(gasLimitUnits, 10).Uint64()
	chainID, err := etherClient.ChainID(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get chain ID")
	}

	transactOpts := b.CreateSignedTransaction(
		chainID,
		etherClient,
		ethereumWallet.Address,
		ethereumWallet.PrivateKey,
		gasLimitUnits,
	)

	bridgeInstance, err := binding.NewBridge(bridgeAddress, etherClient)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create bridge")
	}

	return bridgeInstance, transactOpts, nil
}