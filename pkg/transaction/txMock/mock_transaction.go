package txMock

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hblocks/keyless/pkg/transaction"
	"github.com/pkg/errors"
)

type transactionServiceMock struct {
	send              func(ctx context.Context, request *transaction.TxRequest) (txHash common.Hash, err error)
	waitForReceipt    func(ctx context.Context, txHash common.Hash) (receipt *types.Receipt, err error)
	call              func(ctx context.Context, request *transaction.TxRequest) (result []byte, err error)
	cancelTransaction func(ctx context.Context, originalTxHash common.Hash) (common.Hash, error)
	transactionFee    func(ctx context.Context, txHash common.Hash) (*big.Int, error)
	filterLogs        func(ctx context.Context, query ethereum.FilterQuery) (*[]types.Log, error)
}

func (m *transactionServiceMock) Send(ctx context.Context, request *transaction.TxRequest) (txHash common.Hash, err error) {
	if m.send != nil {
		return m.send(ctx, request)
	}
	return common.Hash{}, errors.New("not implemented")
}

func (m *transactionServiceMock) WaitForReceipt(ctx context.Context, txHash common.Hash) (receipt *types.Receipt, err error) {
	if m.waitForReceipt != nil {
		return m.waitForReceipt(ctx, txHash)
	}
	return nil, errors.New("not implemented")
}

func (m *transactionServiceMock) Call(ctx context.Context, request *transaction.TxRequest) (result []byte, err error) {
	if m.call != nil {
		return m.call(ctx, request)
	}
	return nil, errors.New("not implemented")
}

func (m *transactionServiceMock) FilterLogs(ctx context.Context, query ethereum.FilterQuery) (*[]types.Log, error) {
	if m.filterLogs != nil {
		return m.filterLogs(ctx, query)
	}
	return nil, errors.New("not implemented")
}

func (m *transactionServiceMock) CancelTransaction(ctx context.Context, originalTxHash common.Hash) (common.Hash, error) {
	if m.cancelTransaction != nil {
		return m.cancelTransaction(ctx, originalTxHash)
	}
	return common.Hash{}, errors.New("not implemented")
}

func (m *transactionServiceMock) Close() error {
	return nil
}

// TransactionFee returns fee of transaction
func (m *transactionServiceMock) TransactionFee(ctx context.Context, txHash common.Hash) (*big.Int, error) {
	if m.transactionFee != nil {
		return m.transactionFee(ctx, txHash)
	}
	return big.NewInt(0), nil
}

// Option is the option passed to the mock service
type Option interface {
	apply(*transactionServiceMock)
}

type optionFunc func(*transactionServiceMock)

func (f optionFunc) apply(r *transactionServiceMock) { f(r) }

func WithSendFunc(f func(context.Context, *transaction.TxRequest) (txHash common.Hash, err error)) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.send = f
	})
}

func WithWaitForReceiptFunc(f func(ctx context.Context, txHash common.Hash) (receipt *types.Receipt, err error)) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.waitForReceipt = f
	})
}

func WithCallFunc(f func(ctx context.Context, request *transaction.TxRequest) (result []byte, err error)) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.call = f
	})
}

func WithCancelTransactionFunc(f func(ctx context.Context, originalTxHash common.Hash) (common.Hash, error)) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.cancelTransaction = f
	})
}

func WithTransactionFeeFunc(f func(ctx context.Context, txHash common.Hash) (*big.Int, error)) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.transactionFee = f
	})
}

func New(opts ...Option) transaction.Service {
	mock := new(transactionServiceMock)
	for _, o := range opts {
		o.apply(mock)
	}
	return mock
}

type Call struct {
	abi    *abi.ABI
	to     common.Address
	result []byte
	method string
	params []interface{}
}

func ABICall(abi *abi.ABI, to common.Address, result []byte, method string, params ...interface{}) Call {
	return Call{
		to:     to,
		abi:    abi,
		result: result,
		method: method,
		params: params,
	}
}

func WithABICallSequence(calls ...Call) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.call = func(ctx context.Context, request *transaction.TxRequest) ([]byte, error) {
			if len(calls) == 0 {
				return nil, errors.New("unexpected call")
			}

			call := calls[0]

			data, err := call.abi.Pack(call.method, call.params...)
			if err != nil {
				return nil, err
			}

			if !bytes.Equal(data, request.Data) {
				return nil, fmt.Errorf("wrong data. wanted %x, got %x", data, request.Data)
			}

			if request.To == nil {
				return nil, errors.New("call with no recipient")
			}
			if *request.To != call.to {
				return nil, fmt.Errorf("wrong recipient. wanted %x, got %x", call.to, *request.To)
			}

			calls = calls[1:]

			return call.result, nil
		}
	})
}

func WithABICall(abi *abi.ABI, to common.Address, result []byte, method string, params ...interface{}) Option {
	return WithABICallSequence(ABICall(abi, to, result, method, params...))
}

func WithABISend(abi *abi.ABI, txHash common.Hash, expectedAddress common.Address, expectedValue *big.Int, method string, params ...interface{}) Option {
	return optionFunc(func(s *transactionServiceMock) {
		s.send = func(ctx context.Context, request *transaction.TxRequest) (common.Hash, error) {
			data, err := abi.Pack(method, params...)
			if err != nil {
				return common.Hash{}, err
			}

			if !bytes.Equal(data, request.Data) {
				return common.Hash{}, fmt.Errorf("wrong data. wanted %x, got %x", data, request.Data)
			}

			if request.To != nil && *request.To != expectedAddress {
				return common.Hash{}, fmt.Errorf("sending to wrong contract. wanted %x, got %x", expectedAddress, request.To)
			}
			if request.Value.Cmp(expectedValue) != 0 {
				return common.Hash{}, fmt.Errorf("sending with wrong value. wanted %d, got %d", expectedValue, request.Value)
			}

			return txHash, nil
		}
	})
}
