// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"math/big"
	"testing"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hbakhtiyor/schnorr"
	"github.com/btcsuite/btcd/btcec"
	"crypto/elliptic"
	
)

var (
	// Curve is a KoblitzCurve which implements secp256k1.
	Curve = btcec.S256()
	// One holds a big integer of 1
	One = new(big.Int).SetInt64(1)
	// Two holds a big integer of 2
	Two = new(big.Int).SetInt64(2)
	// Three holds a big integer of 3
	Three = new(big.Int).SetInt64(3)
	// Four holds a big integer of 4
	Four = new(big.Int).SetInt64(4)
	// Seven holds a big integer of 7
	Seven = new(big.Int).SetInt64(7)
	// N2 holds a big integer of N-2
	N2 = new(big.Int).Sub(Curve.N, Two)
)

func TestEIP155Signing(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key,)
	if err != nil {
		t.Fatal(err)
	}

	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != addr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, addr)
	}
	t.Log("")
}

func TestEIP155ChainId(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Protected() {
		t.Fatal("expected tx to be protected")
	}

	if tx.ChainId().Cmp(signer.chainId) != 0 {
		t.Error("expected chainId to be", signer.chainId, "got", tx.ChainId())
	}

	tx = NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	tx, err = SignTx(tx, HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}

	if tx.Protected() {
		t.Error("didn't expect tx to be protected")
	}

	if tx.ChainId().Sign() != 0 {
		t.Error("expected chain id to be 0 got", tx.ChainId())
	}
}

func TestEIP155SigningVitalik(t *testing.T) {
	// Test vectors come from http://vitalik.ca/files/eip155_testvec.txt
	for i, test := range []struct {
		txRlp, addr string
	}{
		{"f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce"},
		{"f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112"},
		{"f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be"},
		{"f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0"},
		{"f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554"},
		{"f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4"},
		{"f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35"},
		{"f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332"},
		{"f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029"},
		{"f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f"},
	} {
		signer := NewEIP155Signer(big.NewInt(1))

		var tx *Transaction
		err := rlp.DecodeBytes(common.Hex2Bytes(test.txRlp), &tx)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}

		from, err := Sender(signer, tx)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}

		addr := common.HexToAddress(test.addr)
		if from != addr {
			t.Errorf("%d: expected %x got %x", i, addr, from)
		}

	}
}

func TestChainId(t *testing.T) {
	key, _ := defaultTestKey()

	tx := NewTransaction(0, common.Address{}, new(big.Int), 0, new(big.Int), nil)

	var err error
	tx, err = SignTx(tx, NewEIP155Signer(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Sender(NewEIP155Signer(big.NewInt(2)), tx)
	if err != ErrInvalidChainId {
		t.Error("expected error:", ErrInvalidChainId)
	}

	_, err = Sender(NewEIP155Signer(big.NewInt(1)), tx)
	if err != nil {
		t.Error("expected no error")
	}
}

//11月14日やったこと
//1, txdata structに公開鍵の格納先Pubkeyを追加
//2, typesにSchnorr.goを追加
//3, TestHoge内でPubkeyに直接公開鍵を追加し、格納
//4, 金曜はドキュメントまとめつつ、SendTransactionがどう動くのかを知りたいかも？
func TestHoge2(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	NonSig := NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	

	//----------------------------------Schnorr用Transactionの作成---------


	//公開鍵はBitcoinのx圧縮形式(今のところ)
	pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	
	//Schnorr.goのUnmarshalを使って公開鍵(x)を導出
	Px, _ := Unmarshal(Curve, pk)
	t.Log(Px)
	//導出したPx(32byte)をTxのPubkeyに格納
	NonSig.data.Pubkey = Px
	t.Log(NonSig.data.Pubkey)
	tx, err := SignTx(NonSig, signer, key,)
	t.Log(tx)

	if err != nil {
		t.Fatal(err)
	}





	//このあとやること
	//1, Sender内部でSchnorrかそうでないかの見極めをどうするか
	// →　どうやらVをyチェックしている関数はない様子
	// →　Vのデフォルト値は27 or 28
	// →　V = chainID * 2 + 8 + (27 or 28)
	// →　Sender内部のCmp()は気になる

	//2, Sender内での検証処理追加
	//3, Txの署名部分にとりあえず署名ぶち込んで署検証してみる(r, s, v, hash)


	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != addr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, addr)
	}
	t.Log(from)
	t.Log(tx.data.V)
	
}





func TestHoge3(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	NonSig := NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	

	//----------------------------------Schnorr用Transactionの作成---------


	//公開鍵はBitcoinのx圧縮形式(今のところ)
	pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	
	//Schnorr.goのUnmarshalを使って公開鍵(x)を導出
	Px, _ := Unmarshal(Curve, pk)
	t.Log(Px)
	//導出したPx(32byte)をTxのPubkeyに格納
	NonSig.data.Pubkey = Px
	t.Log(NonSig.data.Pubkey)
	tx, err := SignTx(NonSig, signer, key,)
	t.Log(tx)

	if err != nil {
		t.Fatal(err)
	}

	//このあとやること
	//1, Sender内部でSchnorrかそうでないかの見極めをどうするか
	// →　どうやらVをyチェックしている関数はない様子
	// →　Vのデフォルト値は27 or 28
	// →　V = chainID * 2 + 8 + (27 or 28)
	// →　Sender内部のCmp()は気になる

	//2, Sender内での検証処理追加
	//3, Txの署名部分にとりあえず署名ぶち込んで署検証してみる(r, s, v, hash)


	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != addr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, addr)
	}
	t.Log(from)
	t.Log(signer.Hash(tx))
	
}






func TestRecoverSchnorr(t *testing.T) {
	//----------------------------------Schnorr用Transactionの作成---------
	var publicKey [33]byte
	
	//公開鍵はBitcoinのx圧縮形式(今のところ)
	pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	copy(publicKey[:], pk)
	key, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
	
	
	//Schnorr.goのUnmarshalを使って公開鍵(x)を導出　→　Schnorr検証に使うための公開鍵
	Px, Py := Unmarshal(Curve, pk)

	//公開鍵(64byte)を作成
	px, py := Px.Bytes(), Py.Bytes()
	Pubkey := [64]byte{}
	copy(Pubkey[:32], px)
	copy(Pubkey[32:], py)
	
	//公開鍵(64byte)からアドレスを生成　→　テスト内での検証に使う
	var addr common.Address
	copy(addr[:], crypto.Keccak256(Pubkey[1:])[12:])


	signer := NewEIP155Signer(big.NewInt(18))
	NonSigned := NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	

	
	
	
	//Schnorrの署名を導出。
	signature, err := schnorr.Sign(key, signer.Hash(NonSigned))
	if err != nil {
		t.Errorf("The signing is failed: %v\n", err)
	  }

	//署名のr, s, v(big.Int)と検証に使う公開鍵(big.Int)をtxにそれぞれ格納
	NonSigned.data.Pubkey = Px
	NonSigned.data.R = new(big.Int).SetBytes(signature[:32])
	NonSigned.data.S = new(big.Int).SetBytes(signature[32:])
	NonSigned.data.V = big.NewInt(44)




	recoveraddr, err := recoverPlainSchnorr(signer.Hash(NonSigned), NonSigned.data.R, NonSigned.data.S, publicKey)
	if err != nil {
		t.Errorf("The Signature is invalid: %v\n", err)
	  }


	if recoveraddr != addr {
		t.Errorf("exected from and address to be equal. Got %x want %x", recoveraddr, addr)
	}

	//
t.Log(recoveraddr, addr)

}



func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	x0 := new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x0, Three, P)
	ySq.Add(ySq, Seven)
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, One)
	d := new(big.Int).Mod(P1, Four)
	P1.Sub(P1, d)
	P1.Div(P1, Four)
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, Two, P).Cmp(ySq) != 0 {
		return
	}
	if y0.Bit(0) != uint(data[0]&1) {
		y0.Sub(P, y0)
	}
	x, y = x0, y0
	return
}

