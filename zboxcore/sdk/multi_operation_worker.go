package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"sync"
	"time"

	"github.com/0chain/common/core/util/wmpt"
	"github.com/0chain/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/0chain/gosdk/core/common"
	"github.com/0chain/gosdk/core/util"
	"github.com/0chain/gosdk/zboxcore/allocationchange"
	"github.com/0chain/gosdk/zboxcore/fileref"
	"github.com/0chain/gosdk/zboxcore/logger"
	l "github.com/0chain/gosdk/zboxcore/logger"

	"github.com/0chain/gosdk/zboxcore/zboxutil"
	"github.com/google/uuid"
)

const (
	DefaultCreateConnectionTimeOut = 45 * time.Second
	StorageV2                      = 1
)

var BatchSize = 6

type MultiOperationOption func(mo *MultiOperation)

func WithRepair() MultiOperationOption {
	return func(mo *MultiOperation) {
		mo.Consensus.consensusThresh = 0
		mo.isRepair = true
	}
}

type Operationer interface {
	Process(allocObj *Allocation, connectionID string) ([]fileref.RefEntity, zboxutil.Uint128, error)
	buildChange(refs []fileref.RefEntity, uid uuid.UUID) []allocationchange.AllocationChange
	Verify(allocObj *Allocation) error
	Completed(allocObj *Allocation)
	Error(allocObj *Allocation, consensus int, err error)
	ProcessChangeV2(trie *wmpt.WeightedMerkleTrie, changeIndex uint64) error
	GetLookupHash(changeIndex uint64) []string
}

type MultiOperation struct {
	connectionID  string
	operations    []Operationer
	allocationObj *Allocation
	ctx           context.Context
	ctxCncl       context.CancelCauseFunc
	operationMask zboxutil.Uint128
	maskMU        *sync.Mutex
	Consensus
	changes   [][]allocationchange.AllocationChange
	changesV2 []allocationchange.AllocationChangeV2
	isRepair  bool
}

func (mo *MultiOperation) createConnectionObj(blobberIdx int) (err error) {

	defer func() {
		if err == nil {
			mo.maskMU.Lock()
			mo.operationMask = mo.operationMask.Or(zboxutil.NewUint128(1).Lsh(uint64(blobberIdx)))
			mo.maskMU.Unlock()
		}
	}()

	var (
		resp           *http.Response
		shouldContinue bool
		latestRespMsg  string

		latestStatusCode int
	)
	blobber := mo.allocationObj.Blobbers[blobberIdx]

	for i := 0; i < 3; i++ {
		err, shouldContinue = func() (err error, shouldContinue bool) {
			body := new(bytes.Buffer)
			formWriter := multipart.NewWriter(body)

			err = formWriter.WriteField("connection_id", mo.connectionID)
			if err != nil {
				return err, false
			}
			formWriter.Close()

			var httpreq *http.Request
			httpreq, err = zboxutil.NewConnectionRequest(blobber.Baseurl, mo.allocationObj.ID, mo.allocationObj.Tx, mo.allocationObj.sig, body, mo.allocationObj.Owner)
			if err != nil {
				l.Logger.Error(blobber.Baseurl, "Error creating new connection request", err)
				return
			}

			httpreq.Header.Add("Content-Type", formWriter.FormDataContentType())
			ctx, cncl := context.WithTimeout(mo.ctx, DefaultCreateConnectionTimeOut)
			defer cncl()
			err = zboxutil.HttpDo(ctx, cncl, httpreq, func(r *http.Response, err error) error {
				resp = r
				return err
			})
			if err != nil {
				logger.Logger.Error("Create Connection: ", err)
				return
			}

			if resp.Body != nil {
				defer resp.Body.Close()
			}
			var respBody []byte
			respBody, err = io.ReadAll(resp.Body)
			if err != nil {
				logger.Logger.Error("Error: Resp ", err)
				return
			}

			latestRespMsg = string(respBody)
			latestStatusCode = resp.StatusCode
			if resp.StatusCode == http.StatusOK {
				l.Logger.Debug(blobber.Baseurl, " connection obj created.")
				return
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				logger.Logger.Error("Got too many request error")
				var r int
				r, err = zboxutil.GetRateLimitValue(resp)
				if err != nil {
					logger.Logger.Error(err)
					return
				}
				time.Sleep(time.Duration(r) * time.Second)
				shouldContinue = true
				return
			}
			l.Logger.Error(blobber.Baseurl, "Response: ", string(respBody))
			err = errors.New("response_error", string(respBody))
			return
		}()

		if err != nil {
			return
		}
		if shouldContinue {
			continue
		}
		return
	}

	err = errors.New("unknown_issue",
		fmt.Sprintf("last status code: %d, last response message: %s", latestStatusCode, latestRespMsg))
	return
}

func (mo *MultiOperation) Process() error {
	l.Logger.Debug("MultiOperation Process start")
	wg := &sync.WaitGroup{}
	if mo.allocationObj.StorageVersion == 0 {
		mo.changes = make([][]allocationchange.AllocationChange, len(mo.operations))
	} else {
		mo.changesV2 = make([]allocationchange.AllocationChangeV2, 0, len(mo.operations))
	}
	ctx := mo.ctx
	ctxCncl := mo.ctxCncl
	defer ctxCncl(nil)
	swg := sizedwaitgroup.New(BatchSize)
	errsSlice := make([]error, len(mo.operations))
	if mo.allocationObj.StorageVersion != StorageV2 {
		mo.operationMask = zboxutil.NewUint128(0)
	}
	for idx, op := range mo.operations {
		uid := util.GetNewUUID()
		swg.Add()
		go func(op Operationer, idx int) {
			defer swg.Done()

			// Check for other goroutines signal
			select {
			case <-ctx.Done():
				return
			default:
			}

			refs, mask, err := op.Process(mo.allocationObj, mo.connectionID) // Process with each blobber
			if err != nil {
				if err != errFileDeleted && err != errNoChange {
					l.Logger.Error(err)
					errsSlice[idx] = errors.New("", err.Error())
					ctxCncl(err)
				}
				return
			}
			mo.maskMU.Lock()
			if mo.allocationObj.StorageVersion == StorageV2 {
				if mo.isRepair {
					mo.operationMask = mo.operationMask.Or(mask)
				} else {
					mo.operationMask = mo.operationMask.And(mask)
				}
				mo.changesV2 = append(mo.changesV2, op)
				mo.maskMU.Unlock()
			} else {
				mo.operationMask = mo.operationMask.Or(mask)
				mo.maskMU.Unlock()
				changes := op.buildChange(refs, uid)
				mo.changes[idx] = changes
			}
		}(op, idx)
	}
	swg.Wait()

	if ctx.Err() != nil {
		err := context.Cause(ctx)
		return err
	}

	// Check consensus
	if mo.operationMask.CountOnes() < mo.consensusThresh {
		majorErr := zboxutil.MajorError(errsSlice)
		if majorErr != nil {
			return errors.New("consensus_not_met",
				fmt.Sprintf("Multioperation failed. Required consensus %d got %d. Major error: %s",
					mo.consensusThresh, mo.operationMask.CountOnes(), majorErr.Error()))
		}
		return nil
	}

	if mo.allocationObj.StorageVersion == StorageV2 && len(mo.changesV2) == 0 {
		return nil
	}

	// Take transpose of mo.change because it will be easier to iterate mo if it contains blobber changes
	// in row instead of column. Currently mo.change[0] contains allocationChange for operation 1 and so on.
	// But we want mo.changes[0] to have allocationChange for blobber 1 and mo.changes[1] to have allocationChange for
	// blobber 2 and so on.
	start := time.Now()
	if mo.allocationObj.StorageVersion != StorageV2 {
		mo.changes = zboxutil.Transpose(mo.changes)
	}

	writeMarkerMutex, err := CreateWriteMarkerMutex(mo.allocationObj)
	if err != nil {
		for _, op := range mo.operations {
			op.Error(mo.allocationObj, 0, err)
		}
		return fmt.Errorf("Operation failed: %s", err.Error())
	}

	l.Logger.Debug("Trying to lock write marker.....")
	if singleClientMode {
		mo.allocationObj.commitMutex.Lock()
	} else {
		err = writeMarkerMutex.Lock(mo.ctx, &mo.operationMask, mo.maskMU,
			mo.allocationObj.Blobbers, &mo.Consensus, 0, time.Minute, mo.connectionID)
		if err != nil {
			return fmt.Errorf("Operation failed: %s", err.Error())
		}
	}
	logger.Logger.Debug("[writemarkerLocked]", time.Since(start).Milliseconds())
	start = time.Now()
	status := Commit
	if !mo.isRepair && !mo.allocationObj.checkStatus {
		status, _, err = mo.allocationObj.CheckAllocStatus()
		if err != nil {
			logger.Logger.Error("Error checking allocation status", err)
			if singleClientMode {
				mo.allocationObj.commitMutex.Unlock()
			} else {
				writeMarkerMutex.Unlock(mo.ctx, mo.operationMask, mo.allocationObj.Blobbers, time.Minute, mo.connectionID) //nolint: errcheck
			}
			return fmt.Errorf("Check allocation status failed: %s", err.Error())
		}
		if status == Repair {
			if singleClientMode {
				mo.allocationObj.commitMutex.Unlock()
			} else {
				writeMarkerMutex.Unlock(mo.ctx, mo.operationMask, mo.allocationObj.Blobbers, time.Minute, mo.connectionID) //nolint: errcheck
			}
			for _, op := range mo.operations {
				op.Error(mo.allocationObj, 0, ErrRepairRequired)
			}
			return ErrRepairRequired
		}
	}
	if singleClientMode {
		mo.allocationObj.checkStatus = true
		defer mo.allocationObj.commitMutex.Unlock()
	} else {
		defer writeMarkerMutex.Unlock(mo.ctx, mo.operationMask, mo.allocationObj.Blobbers, time.Minute, mo.connectionID) //nolint: errcheck
	}
	if status != Commit {
		for _, op := range mo.operations {
			op.Error(mo.allocationObj, 0, ErrRetryOperation)
		}
		return ErrRetryOperation
	}
	logger.Logger.Debug("[checkAllocStatus]", time.Since(start).Milliseconds())
	mo.Consensus.Reset()
	var pos uint64
	if !mo.isRepair && mo.allocationObj.StorageVersion == StorageV2 {
		for i := mo.operationMask; !i.Equals64(0); i = i.And(zboxutil.NewUint128(1).Lsh(pos).Not()) {
			pos = uint64(i.TrailingZeros())
			if mo.allocationObj.Blobbers[pos].AllocationRoot != mo.allocationObj.allocationRoot {
				l.Logger.Info("Blobber allocation root mismatch", mo.allocationObj.Blobbers[pos].Baseurl, mo.allocationObj.Blobbers[pos].AllocationRoot, mo.allocationObj.allocationRoot)
				mo.operationMask = mo.operationMask.And(zboxutil.NewUint128(1).Lsh(pos).Not())
			}
		}
	}
	activeBlobbers := mo.operationMask.CountOnes()
	if activeBlobbers < mo.consensusThresh {
		l.Logger.Error("consensus not met", activeBlobbers, mo.consensusThresh)
		return errors.New("consensus_not_met", fmt.Sprintf("Active blobbers %d is less than consensus threshold %d", activeBlobbers, mo.consensusThresh))
	}
	if mo.allocationObj.StorageVersion == StorageV2 {
		return mo.commitV2()
	}
	commitReqs := make([]*CommitRequest, activeBlobbers)
	start = time.Now()
	wg.Add(activeBlobbers)
	var counter = 0
	timestamp := int64(common.Now())
	for i := mo.operationMask; !i.Equals64(0); i = i.And(zboxutil.NewUint128(1).Lsh(pos).Not()) {
		pos = uint64(i.TrailingZeros())
		commitReq := &CommitRequest{
			ClientId:     mo.allocationObj.Owner,
			allocationID: mo.allocationObj.ID,
			allocationTx: mo.allocationObj.Tx,
			sig:          mo.allocationObj.sig,
			blobber:      mo.allocationObj.Blobbers[pos],
			connectionID: mo.connectionID,
			wg:           wg,
			timestamp:    timestamp,
			blobberInd:   pos,
		}

		commitReq.changes = append(commitReq.changes, mo.changes[pos]...)
		commitReqs[counter] = commitReq
		l.Logger.Debug("Commit request sending to blobber ", commitReq.blobber.Baseurl)
		go AddCommitRequest(commitReq)
		counter++
	}
	wg.Wait()
	logger.Logger.Debug("[commitRequests]", time.Since(start).Milliseconds())
	rollbackMask := zboxutil.NewUint128(0)
	errSlice := make([]error, len(commitReqs))
	for idx, commitReq := range commitReqs {
		if commitReq.result != nil {
			if commitReq.result.Success {
				l.Logger.Debug("Commit success", commitReq.blobber.Baseurl)
				if !mo.isRepair {
					rollbackMask = rollbackMask.Or(zboxutil.NewUint128(1).Lsh(commitReq.blobberInd))
				}
				mo.consensus++
			} else {
				errSlice[idx] = errors.New("commit_failed", commitReq.result.ErrorMessage)
				l.Logger.Error("Commit failed", commitReq.blobber.Baseurl, commitReq.result.ErrorMessage)
			}
		} else {
			l.Logger.Debug("Commit result not set", commitReq.blobber.Baseurl)
		}
	}

	if !mo.isConsensusOk() {
		err = zboxutil.MajorError(errSlice)
		if mo.getConsensus() != 0 {
			l.Logger.Info("Rolling back changes on minority blobbers")
			mo.allocationObj.RollbackWithMask(rollbackMask)
		}
		for _, op := range mo.operations {
			op.Error(mo.allocationObj, mo.getConsensus(), err)
		}
		return err
	} else {
		for _, op := range mo.operations {
			op.Completed(mo.allocationObj)
		}
	}

	return nil

}

func (mo *MultiOperation) commitV2() error {

	rootMap := make(map[string]zboxutil.Uint128)
	var pos uint64
	for i := mo.operationMask; !i.Equals64(0); i = i.And(zboxutil.NewUint128(1).Lsh(pos).Not()) {
		pos = uint64(i.TrailingZeros())
		rootMap[mo.allocationObj.Blobbers[pos].AllocationRoot] = rootMap[mo.allocationObj.Blobbers[pos].AllocationRoot].Or(zboxutil.NewUint128(1).Lsh(pos))
	}
	commitReqs := make([]*CommitRequestV2, len(rootMap))
	counter := 0
	timestamp := int64(common.Now())
	wg := &sync.WaitGroup{}
	for _, mask := range rootMap {
		wg.Add(1)
		var changes []allocationchange.AllocationChangeV2
		if len(rootMap) > 1 {
			changes = make([]allocationchange.AllocationChangeV2, 0, len(mo.operations))
			changes = append(changes, mo.changesV2...)
		} else {
			changes = mo.changesV2
		}
		commitReq := &CommitRequestV2{
			allocationObj:   mo.allocationObj,
			connectionID:    mo.connectionID,
			sig:             mo.allocationObj.sig,
			wg:              wg,
			timestamp:       timestamp,
			commitMask:      mask,
			consensusThresh: mo.consensusThresh,
			changes:         changes,
			isRepair:        mo.isRepair,
		}
		commitReqs[counter] = commitReq
		counter++
		go AddCommitRequest(commitReq)
	}
	wg.Wait()
	rollbackMask := zboxutil.NewUint128(0)
	errSlice := make([]error, len(commitReqs))
	for idx, commitReq := range commitReqs {
		if commitReq.result != nil {
			mo.consensus += commitReq.commitMask.CountOnes()
			if !commitReq.result.Success {
				errSlice[idx] = errors.New("commit_failed", commitReq.result.ErrorMessage)
				l.Logger.Error("Commit failed ", commitReq.result.ErrorMessage)
			}
			if !mo.isRepair {
				rollbackMask = rollbackMask.Or(commitReq.commitMask)
			}
		} else {
			l.Logger.Debug("Commit result not set")
		}
	}
	if !mo.isConsensusOk() {
		err := zboxutil.MajorError(errSlice)
		if err == nil {
			err = errors.New("consensus_not_met", fmt.Sprintf("Successfully committed to %d blobbers, but required %d", mo.consensus, len(mo.allocationObj.Blobbers)))
		}
		if mo.getConsensus() != 0 {
			l.Logger.Info("Rolling back changes on minority blobbers")
			mo.allocationObj.RollbackWithMask(rollbackMask)
			mo.allocationObj.checkStatus = false
		}
		for _, op := range mo.operations {
			op.Error(mo.allocationObj, mo.getConsensus(), err)
		}
		return err
	} else {
		for _, op := range mo.operations {
			op.Completed(mo.allocationObj)
		}
	}
	return nil
}
