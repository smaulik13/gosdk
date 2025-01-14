package sdk

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/0chain/errors"
	"github.com/0chain/gosdk/core/client"
	"github.com/0chain/gosdk/core/encryption"
	"github.com/0chain/gosdk/core/transaction"
	"github.com/0chain/gosdk/zboxcore/logger"
	"go.uber.org/zap"
)

// CreateAllocationForOwner creates a new allocation with the given options (txn: `storagesc.new_allocation_request`).
//
//   - owner is the client id of the owner of the allocation.
//   - ownerpublickey is the public key of the owner of the allocation.
//   - datashards is the number of data shards for the allocation.
//   - parityshards is the number of parity shards for the allocation.
//   - size is the size of the allocation.
//   - readPrice is the read price range for the allocation (Reads in Züs are free!).
//   - writePrice is the write price range for the allocation.
//   - lock is the lock value for the transaction (how much tokens to lock to the allocation, in SAS).
//   - preferredBlobberIds is a list of preferred blobber ids for the allocation.
//   - thirdPartyExtendable is a flag indicating whether the allocation can be extended by a third party.
//   - fileOptionsParams is the file options parameters for the allocation, which control the usage permissions of the files in the allocation.
//
// returns the hash of the transaction, the nonce of the transaction, the transaction object and an error if any.
func CreateAllocationForOwner(
	owner, ownerpublickey string,
	datashards, parityshards int, size int64,
	readPrice, writePrice PriceRange,
	lock uint64, preferredBlobberIds, blobberAuthTickets []string, thirdPartyExtendable, IsEnterprise, force bool, fileOptionsParams *FileOptionsParameters,
) (hash string, nonce int64, txn *transaction.Transaction, err error) {

	if lock > math.MaxInt64 {
		return "", 0, nil, errors.New("invalid_lock", "int64 overflow on lock value")
	}

	if datashards < 1 || parityshards < 1 {
		return "", 0, nil, errors.New("allocation_validation_failed", "atleast 1 data and 1 parity shards are required")
	}

	allocationRequest, err := getNewAllocationBlobbers(
		StorageV2, datashards, parityshards, size, readPrice, writePrice, preferredBlobberIds, blobberAuthTickets, force)
	if err != nil {
		return "", 0, nil, errors.New("failed_get_allocation_blobbers", "failed to get blobbers for allocation: "+err.Error())
	}

	if !client.IsSDKInitialized() {
		return "", 0, nil, sdkNotInitialized
	}

	if client.PublicKey() == ownerpublickey {
		privateSigningKey, err := generateOwnerSigningKey(ownerpublickey, owner)
		if err != nil {
			return "", 0, nil, errors.New("failed_generate_owner_signing_key", "failed to generate owner signing key: "+err.Error())
		}
		pub := privateSigningKey.Public().(ed25519.PublicKey)
		pk := hex.EncodeToString(pub)
		allocationRequest["owner_signing_public_key"] = pk
	}

	allocationRequest["owner_id"] = owner
	allocationRequest["owner_public_key"] = ownerpublickey
	allocationRequest["third_party_extendable"] = thirdPartyExtendable
	allocationRequest["file_options_changed"], allocationRequest["file_options"] = calculateAllocationFileOptions(63 /*0011 1111*/, fileOptionsParams)
	allocationRequest["is_enterprise"] = IsEnterprise
	allocationRequest["storage_version"] = StorageV2

	var sn = transaction.SmartContractTxnData{
		Name:      transaction.NEW_ALLOCATION_REQUEST,
		InputArgs: allocationRequest,
	}
	hash, _, nonce, txn, err = storageSmartContractTxnValue(sn, lock)
	return
}

// CreateFreeAllocation creates a new free allocation (txn: `storagesc.free_allocation_request`).
//   - marker is the marker for the free allocation.
//   - value is the value of the free allocation.
//
// returns the hash of the transaction, the nonce of the transaction and an error if any.
func CreateFreeAllocation(marker string, value uint64) (string, int64, error) {
	if !client.IsSDKInitialized() {
		return "", 0, sdkNotInitialized
	}

	recipientPublicKey := client.PublicKey()

	var input = map[string]interface{}{
		"recipient_public_key": recipientPublicKey,
		"marker":               marker,
	}

	blobbers, err := GetFreeAllocationBlobbers(input)
	if err != nil {
		return "", 0, err
	}

	input["blobbers"] = blobbers

	var sn = transaction.SmartContractTxnData{
		Name:      transaction.NEW_FREE_ALLOCATION,
		InputArgs: input,
	}
	hash, _, n, _, err := storageSmartContractTxnValue(sn, value)
	return hash, n, err
}

// UpdateAllocation sends an update request for an allocation (txn: `storagesc.update_allocation_request`)
//
//   - size is the size of the allocation.
//   - extend is a flag indicating whether to extend the allocation.
//   - allocationID is the id of the allocation.
//   - lock is the lock value for the transaction (how much tokens to lock to the allocation, in SAS).
//   - addBlobberId is the id of the blobber to add to the allocation.
//   - addBlobberAuthTicket is the auth ticket of the blobber to add to the allocation, in case the blobber is restricted.
//   - removeBlobberId is the id of the blobber to remove from the allocation.
//   - setThirdPartyExtendable is a flag indicating whether the allocation can be extended by a third party.
//   - fileOptionsParams is the file options parameters for the allocation, which control the usage permissions of the files in the allocation.
//
// returns the hash of the transaction, the nonce of the transaction and an error if any.
func UpdateAllocation(
	size int64,
	extend bool,
	allocationID string,
	lock uint64,
	addBlobberId, addBlobberAuthTicket, removeBlobberId, ownerSigninPublicKey string,
	setThirdPartyExtendable bool, fileOptionsParams *FileOptionsParameters,
) (hash string, nonce int64, err error) {

	if lock > math.MaxInt64 {
		return "", 0, errors.New("invalid_lock", "int64 overflow on lock value")
	}

	if !client.IsSDKInitialized() {
		return "", 0, sdkNotInitialized
	}

	alloc, err := GetAllocationForUpdate(allocationID)
	if err != nil {
		return "", 0, allocationNotFound
	}

	updateAllocationRequest := make(map[string]interface{})
	updateAllocationRequest["owner_id"] = client.Id()
	updateAllocationRequest["owner_public_key"] = ""
	updateAllocationRequest["id"] = allocationID
	updateAllocationRequest["size"] = size
	updateAllocationRequest["extend"] = extend
	updateAllocationRequest["add_blobber_id"] = addBlobberId
	updateAllocationRequest["add_blobber_auth_ticket"] = addBlobberAuthTicket
	updateAllocationRequest["remove_blobber_id"] = removeBlobberId
	updateAllocationRequest["set_third_party_extendable"] = setThirdPartyExtendable
	updateAllocationRequest["owner_signing_public_key"] = ownerSigninPublicKey
	updateAllocationRequest["file_options_changed"], updateAllocationRequest["file_options"] = calculateAllocationFileOptions(alloc.FileOptions, fileOptionsParams)

	sn := transaction.SmartContractTxnData{
		Name:      transaction.STORAGESC_UPDATE_ALLOCATION,
		InputArgs: updateAllocationRequest,
	}
	hash, _, nonce, _, err = storageSmartContractTxnValue(sn, lock)
	return
}

// StakePoolLock locks tokens in a stake pool.
// This function is the entry point for the staking operation.
// Provided the provider type and provider ID, the value is locked in the stake pool between the SDK client and the provider.
// Based on the locked amount, the client will get rewards as share of the provider's rewards.
//   - providerType: provider type
//   - providerID: provider ID
//   - value: value to lock
//   - fee: transaction fee
func StakePoolLock(providerType ProviderType, providerID string, value, fee uint64) (hash string, nonce int64, err error) {
	if !client.IsSDKInitialized() {
		return "", 0, sdkNotInitialized
	}

	if providerType == 0 {
		return "", 0, errors.New("stake_pool_lock", "provider is required")
	}

	if providerID == "" {
		return "", 0, errors.New("stake_pool_lock", "provider_id is required")
	}

	spr := stakePoolRequest{
		ProviderType: providerType,
		ProviderID:   providerID,
	}

	var sn = transaction.SmartContractTxnData{
		InputArgs: &spr,
	}

	var scAddress string
	switch providerType {
	case ProviderBlobber, ProviderValidator:
		scAddress = STORAGE_SCADDRESS
		sn.Name = transaction.STORAGESC_STAKE_POOL_LOCK
	case ProviderMiner, ProviderSharder:
		scAddress = MINERSC_SCADDRESS
		sn.Name = transaction.MINERSC_LOCK
	case ProviderAuthorizer:
		scAddress = ZCNSC_SCADDRESS
		sn.Name = transaction.ZCNSC_LOCK
	default:
		return "", 0, errors.Newf("stake_pool_lock", "unsupported provider type: %v", providerType)
	}

	hash, _, nonce, _, err = transaction.SmartContractTxnValueFeeWithRetry(scAddress, sn, value, fee, true)
	return
}

// StakePoolUnlock unlocks a stake pool tokens. If tokens can't be unlocked due
// to opened offers, then it returns time where the tokens can be unlocked,
// marking the pool as 'want to unlock' to avoid its usage in offers in the
// future. The time is maximal time that can be lesser in some cases. To
// unlock tokens can't be unlocked now, wait the time and unlock them (call
// this function again).
//   - providerType: provider type
//   - providerID: provider ID
//   - fee: transaction fee
func StakePoolUnlock(providerType ProviderType, providerID string, fee uint64) (unstake int64, nonce int64, err error) {
	if !client.IsSDKInitialized() {
		return 0, 0, sdkNotInitialized
	}

	if providerType == 0 {
		return 0, 0, errors.New("stake_pool_lock", "provider is required")
	}

	if providerID == "" {
		return 0, 0, errors.New("stake_pool_lock", "provider_id is required")
	}

	spr := stakePoolRequest{
		ProviderType: providerType,
		ProviderID:   providerID,
	}

	var sn = transaction.SmartContractTxnData{
		InputArgs: &spr,
	}

	var scAddress string
	switch providerType {
	case ProviderBlobber, ProviderValidator:
		scAddress = STORAGE_SCADDRESS
		sn.Name = transaction.STORAGESC_STAKE_POOL_UNLOCK
	case ProviderMiner, ProviderSharder:
		scAddress = MINERSC_SCADDRESS
		sn.Name = transaction.MINERSC_UNLOCK
	case ProviderAuthorizer:
		scAddress = ZCNSC_SCADDRESS
		sn.Name = transaction.ZCNSC_UNLOCK
	default:
		return 0, 0, errors.Newf("stake_pool_unlock", "unsupported provider type: %v", providerType)
	}

	var out string
	if _, out, nonce, _, err = transaction.SmartContractTxnValueFeeWithRetry(scAddress, sn, 0, fee, true); err != nil {
		return // an error
	}

	var spuu stakePoolLock
	if err = json.Unmarshal([]byte(out), &spuu); err != nil {
		return
	}

	return spuu.Amount, nonce, nil
}

// WritePoolLock locks given number of tokes for given duration in read pool.
//   - allocID: allocation ID
//   - tokens: number of tokens to lock
//   - fee: transaction fee
func WritePoolLock(allocID string, tokens, fee uint64) (hash string, nonce int64, err error) {
	if !client.IsSDKInitialized() {
		return "", 0, sdkNotInitialized
	}

	type lockRequest struct {
		AllocationID string `json:"allocation_id"`
	}

	var req lockRequest
	req.AllocationID = allocID

	var sn = transaction.SmartContractTxnData{
		Name:      transaction.STORAGESC_WRITE_POOL_LOCK,
		InputArgs: &req,
	}

	hash, _, nonce, _, err = transaction.SmartContractTxnValueFeeWithRetry(STORAGE_SCADDRESS, sn, tokens, fee, true)
	return
}

// WritePoolUnlock unlocks ALL tokens of a write pool. Needs to be cancelled first.
//   - allocID: allocation ID
//   - fee: transaction fee
func WritePoolUnlock(allocID string, fee uint64) (hash string, nonce int64, err error) {
	if !client.IsSDKInitialized() {
		return "", 0, sdkNotInitialized
	}

	type unlockRequest struct {
		AllocationID string `json:"allocation_id"`
	}

	var req unlockRequest
	req.AllocationID = allocID

	var sn = transaction.SmartContractTxnData{
		Name:      transaction.STORAGESC_WRITE_POOL_UNLOCK,
		InputArgs: &req,
	}
	hash, _, nonce, _, err = transaction.SmartContractTxnValueFeeWithRetry(STORAGE_SCADDRESS, sn, 0, fee, true)
	return
}

func generateOwnerSigningKey(ownerPublicKey, ownerID string) (ed25519.PrivateKey, error) {
	if ownerPublicKey == "" {
		return nil, errors.New("owner_public_key_required", "owner public key is required")
	}
	hashData := fmt.Sprintf("%s:%s", ownerPublicKey, "owner_signing_public_key")
	sig, err := client.Sign(encryption.Hash(hashData), ownerID)
	if err != nil {
		logger.Logger.Error("error during sign", zap.Error(err))
		return nil, err
	}
	//use this signature as entropy to generate ecdsa key pair
	decodedSig, _ := hex.DecodeString(sig)
	privateSigningKey := ed25519.NewKeyFromSeed(decodedSig[:32])
	return privateSigningKey, nil
}
