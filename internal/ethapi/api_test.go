


package ethapi

import (
	//"bytes"
	//"crypto/ecdsa"
	//"encoding/json"
	//"math/big"
	"testing"
	
	

	//"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	//"github.com/tyler-smith/go-bip39"
	
)


func TestHoge(t *testing.T) {T
	
	//var tx *Transaction
	//var ethDefaultConf = eth.DefaultConfig
	nodeDefaultConf := node.DefaultConfig
	
	n, err := node.New(&nodeDefaultConf)
	if err != nil {
		t.Errorf("New() get error")
	}

	
	ctx := n.Start()
	if err != nil {
		t.Errorf("NewServiceContext() get error")
	}

	

	t.Log(ctx)
	

	
	
}





