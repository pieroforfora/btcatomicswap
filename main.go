// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
  "log"
  //"io/ioutil"
  "net/http"


	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	rpc "github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"golang.org/x/crypto/ripemd160"
)

const verify = true


const txVersion = 2

var (
	chainParams = &chaincfg.MainNetParams
)

var (
	flagset     = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag = flagset.String("s", "localhost", "host[:port] of Bitcoin Core wallet RPC server")
	rpcuserFlag = flagset.String("rpcuser", "", "username for wallet RPC authentication")
	rpcpassFlag = flagset.String("rpcpass", "", "password for wallet RPC authentication")
	testnetFlag = flagset.Bool("testnet", false, "use testnet network")
	regTestFlag = flagset.Bool("regtest", false, "use regtest network")
  ltInitiate = flagset.Int("ltInitiate", 48, "min initiate locktime in hours ")
  ltPartecipate = flagset.Int("ltPartecipate", 24, "min partecipate locktime in hours")
  sS = flagset.Int64("secretSize", 32, "min partecipate locktime in hours")

)

var secretSize = *sS
// There are two directions that the atomic swap can be performed, as the
// initiator can be on either chain.  This tool only deals with creating the
// Bitcoin transactions for these swaps.  A second tool should be used for the
// transaction on the other chain.  Any chain can be used so long as it supports
// OP_SHA256 and OP_CHECKLOCKTIMEVERIFY.
//
// Example scenerios using bitcoin as the second chain:
//
// Scenerio 1:
//   cp1 initiates (dcr)
//   cp2 participates with cp1 H(S) (btc)
//   cp1 redeems btc revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems dcr with S
//
// Scenerio 2:
//   cp1 initiates (btc)
//   cp2 participates with cp1 H(S) (dcr)
//   cp1 redeems dcr revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems btc with S

func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: btcatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  initiate <participant address> <amount>")
		fmt.Println("  participate <initiator address> <amount> <secret hash>")
		fmt.Println("  redeem <contract> <contract transaction> <secret>")
		fmt.Println("  refund <contract> <contract transaction>")
		fmt.Println("  extractsecret <redemption transaction> <secret hash>")
		fmt.Println("  auditcontract <contract> <contract transaction>")
		fmt.Println("  daemon")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(*rpc.Client) error
}


type daemonCommand interface {
	runCommand(*rpc.Client) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type initiateCmd struct {
	cp2Addr *btcutil.AddressPubKeyHash
	amount  btcutil.Amount
}

type participateCmd struct {
	cp1Addr    *btcutil.AddressPubKeyHash
	amount     btcutil.Amount
	secretHash []byte
}

type redeemCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
	secret     []byte
}

type refundCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
}

type extractSecretCmd struct {
	redemptionTx *wire.MsgTx
	secretHash   []byte
}

type auditContractCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
}

type contractArgsCmd struct {
  them       *btcutil.AddressPubKeyHash
  amount     uint64
  locktime   int64
  secretHash []byte
  secret     []byte
}
type walletBalanceCmd struct {}
type atomicSwapParamsCmd struct {}


type spendArgsCmd struct {
  contract    []byte
  contractTx  *wire.MsgTx
  secret      []byte

}



func main() {
	err, showUsage := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if showUsage {
		flagset.Usage()
	}
	if err != nil || showUsage {
		os.Exit(1)
	}
}

func checkCmdArgLength(args []string, required int) (nArgs int) {
	if len(args) < required {
		return 0
	}
	for i, arg := range args[:required] {
		if len(arg) != 1 && strings.HasPrefix(arg, "-") {
			return i
		}
	}
	return required
}

func run() (err error, showUsage bool) {
	flagset.Parse(os.Args[1:])
	args := flagset.Args()
	if len(args) == 0 {
		return nil, true
	}
	cmdArgs := 0
	switch args[0] {
	case "initiate":
		cmdArgs = 2
	case "participate":
		cmdArgs = 3
	case "redeem":
		cmdArgs = 3
	case "refund":
		cmdArgs = 2
	case "extractsecret":
		cmdArgs = 2
	case "auditcontract":
		cmdArgs = 2
  case "daemon":
    cmdArgs = 0
	default:
		return fmt.Errorf("unknown command %v", args[0]), true
	}
	nArgs := checkCmdArgLength(args[1:], cmdArgs)
	flagset.Parse(args[1+nArgs:])
	if nArgs < cmdArgs {
		return fmt.Errorf("%s: too few arguments", args[0]), true
	}
	if flagset.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flagset.Arg(0)), true
	}

	if *testnetFlag {
		chainParams = &chaincfg.TestNet3Params
	}

	if *regTestFlag {
		chainParams = &chaincfg.RegressionNetParams
	}
	var cmd command
	switch args[0] {
	case "initiate":
    cmd,err = parseBuildArgs(BuildContractInput{
        Them:       args[1],
        Amount:     args[2],
    })
    if err != nil{
      panic(err)
    }

	case "participate":
    cmd,err = parseBuildArgs(BuildContractInput{
        Them:       args[1],
        Amount:     args[2],
        SecretHash: &args[3],
    })
    if err != nil{
      panic(err)
    }

	case "redeem":
    cmd,err = parseSpendArgs(SpendContractInput{
      Contract:   args[1],
      Tx:         args[2],
      Secret:     &args[3],
    })
    if err != nil{
      panic(err)
    }

	case "refund":
    cmd,err = parseSpendArgs(SpendContractInput{
      Contract: args[1],
      Tx:       args[2],
    })
    if err != nil{
      panic(err)
    }

	case "extractsecret":
   cmd,err = parseExtractSecretArgs(ExtractSecretInput{
      Tx:         args[1],
      SecretHash: args[2],
    })
    if err != nil{
      panic(err)
    }

	case "auditcontract":
   cmd,err = parseAuditContractArgs(AuditContractInput{
      Contract: args[1],
      Tx:       args[2],
    })
    if err != nil{
      panic(err)
    }

  case "daemon":
    restApiRequestsHandlers()
    fmt.Println("Server is up and running...")
    log.Fatal(http.ListenAndServe(":8080", nil))
    return nil,false

	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}
  client,err := getClient()
  if err!= nil{
    return err,true
  }
	err = cmd.runCommand(client)
	return err, false
}
func getClient() (*rpc.Client,error){
  connect, err := normalizeAddress(*connectFlag, walletPort(chainParams))
  if err != nil {
    return nil,fmt.Errorf("wallet server address: %v", err)
  }

  connConfig := &rpc.ConnConfig{
    Host:         connect,
    User:         *rpcuserFlag,
    Pass:         *rpcpassFlag,
    DisableTLS:   true,
    HTTPPostMode: true,
  }
  client, err := rpc.New(connConfig, nil)
  if err != nil {
    return nil,fmt.Errorf("rpc connect: %v", err)
  }
  defer func() {
    client.Shutdown()
    client.WaitForShutdown()
  }()
  return client,nil
}

func addressFromString(arg string) (*btcutil.AddressPubKeyHash, error){
  cp2Addr, err := btcutil.DecodeAddress(arg, chainParams)
  if err != nil {
    return nil, fmt.Errorf("failed to decode participant address: %v", err)
  }
  if !cp2Addr.IsForNet(chainParams) {
    return nil,fmt.Errorf("participant address is not "+
      "intended for use on %v", chainParams.Name)
  }
  cp2AddrP2PKH, ok := cp2Addr.(*btcutil.AddressPubKeyHash)
  if !ok {
    return nil, errors.New("participant address is not P2PKH")
  }
  return cp2AddrP2PKH,nil
}

func amountFromString(samount string)(*uint64, error){
  amountF64, err := strconv.ParseFloat(samount, 64)
  if err != nil {
    return nil, errors.New(fmt.Sprintf("failed to decode amount: %v", err))
  }
  amount := uint64(amountF64) //uint64(constants.SompiPerKaspa)
  return &amount,nil
}

func contractFromString(scontract string)([]byte,error){
  contract, err := hex.DecodeString(scontract)
  if err != nil {
    return nil, errors.New(fmt.Sprintf("failed to decode contract: %v", err))
  }
  return contract,nil
}

func secretFromString(ssecret *string)([]byte,error){
  if ssecret == nil || *ssecret == ""{
    return nil,nil
  }
  secret, err := hex.DecodeString(*ssecret)
  if err != nil {
    return nil, errors.New(fmt.Sprintf("failed to decode secret: %v", err))
  }
  return secret,nil
}

func secretHashFromString(ssecretHash *string)([]byte,error){
  secretHash, err := hex.DecodeString(*ssecretHash)
  if err != nil {
    return nil, errors.New(fmt.Sprintf("failed to decode secretHash: %v", err))
  }
  if len(secretHash) != sha256.Size {
    return nil, errors.New("secret hash has wrong size")
  }
  return secretHash,nil
}

func msgTxFromString(strtx *string)(*wire.MsgTx,error){
 contractTxBytes, err := hex.DecodeString(*strtx)
    if err != nil {
      return nil, fmt.Errorf("failed to decode contract transaction: %v", err)
    }
    var contractTx wire.MsgTx
    err = contractTx.Deserialize(bytes.NewReader(contractTxBytes))
    if err != nil {
      return nil, fmt.Errorf("failed to decode contract transaction: %v", err)
    }
  return &contractTx,nil
}

func getSecret()([]byte,[]byte, error){

  //var secret [int(secretSize)]byte
  var secret =make([]byte,secretSize)
  _, err := rand.Read(secret[:])
  if err != nil {
    return nil,nil,err
  }
  secretHash := sha256Hash(secret[:])
  return secret[:],secretHash,nil
}

func parseBuildArgs(args BuildContractInput) (*contractArgsCmd,error){
  cp2AddrP2PKH,err := addressFromString(args.Them)
  if err != nil {
    return nil, err
  }
  amount,err := amountFromString(args.Amount)
  if err != nil {
    return nil, err
  }

  var secret []byte
  var secretHash []byte
  var lockTime int64
  if args.SecretHash == nil || *args.SecretHash == ""{
    secret,secretHash,_ = getSecret()
    lockTime = int64(time.Now().Add(time.Duration(*ltInitiate) * time.Hour).Unix())
  }else{
    secret = nil
    secretHash,err = secretHashFromString(args.SecretHash)
    if err != nil{
      return nil, err
    }
    lockTime = int64(time.Now().Add(time.Duration(*ltPartecipate) * time.Hour).Unix())
}
  return &contractArgsCmd{
    them:       cp2AddrP2PKH,
    amount:     *amount,
    secretHash: secretHash,
    secret:     secret,
    locktime:   lockTime,
  },nil

}

func parseSpendArgs(args SpendContractInput) (*spendArgsCmd,error){
    contract, err := contractFromString(args.Contract)
    if err!=nil{
      return nil, err
    }
    contractTx, err := msgTxFromString(&args.Tx)
    if err!=nil{
      return nil, err
    }
    secret, err := secretFromString(args.Secret)
    if err!=nil{
      return nil, err
    }

    return &spendArgsCmd{
      contract:   contract,
      contractTx: contractTx,
      secret:     secret,
    }, nil

}

func parseExtractSecretArgs(args ExtractSecretInput) (*extractSecretCmd,error){
  secretHash, err := secretHashFromString(&args.SecretHash)
  if err != nil {
    return nil, err
  }
  redeemTx, err := msgTxFromString(&args.Tx)
  if err !=nil{
    return nil, err
  }
  return &extractSecretCmd{
    redemptionTx: redeemTx,
    secretHash:   secretHash,
  },nil

}

func parseAuditContractArgs(args AuditContractInput) (*auditContractCmd,error){
  contractTx, err := msgTxFromString(&args.Tx)
  if err !=nil{
    return nil, errors.New(fmt.Sprintf("failed to decode redeemTx: %v", err))
  }
  contract, err := contractFromString(args.Contract)
  return &auditContractCmd{
    contract:   contract,
    contractTx: contractTx,
  },nil

}

func normalizeAddress(addr string, defaultPort string) (hostport string, err error) {
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		return "", origErr
	}
	return addr, nil
}

func walletPort(params *chaincfg.Params) string {
	switch params {
	case &chaincfg.MainNetParams:
		return "8332"
	case &chaincfg.TestNet3Params:
		return "18332"
	default:
		return ""
	}
}

// createSig creates and returns the serialized raw signature and compressed
// pubkey for a transaction input signature.  Due to limitations of the Bitcoin
// Core RPC API, this requires dumping a private key and signing in the client,
// rather than letting the wallet sign.
func createSig(tx *wire.MsgTx, idx int, pkScript []byte, addr btcutil.Address,
	c *rpc.Client) (sig, pubkey []byte, err error) {

	wif, err := c.DumpPrivKey(addr)
	if err != nil {
		return nil, nil, err
	}
	sig, err = txscript.RawTxInSignature(tx, idx, pkScript, txscript.SigHashAll, wif.PrivKey)
	if err != nil {
		return nil, nil, err
	}
	return sig, wif.PrivKey.PubKey().SerializeCompressed(), nil
}

// fundRawTransaction calls the fundrawtransaction JSON-RPC method.  It is
// implemented manually as client support is currently missing from the
// btcd/rpcclient package.
func fundRawTransaction(c *rpc.Client, tx *wire.MsgTx, feePerKb btcutil.Amount) (fundedTx *wire.MsgTx, fee btcutil.Amount, err error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	param0, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, 0, err
	}
	param1, err := json.Marshal(struct {
		FeeRate float64 `json:"feeRate"`
	}{
		FeeRate: feePerKb.ToBTC(),
	})
	if err != nil {
		return nil, 0, err
	}
	params := []json.RawMessage{param0, param1}
	rawResp, err := c.RawRequest("fundrawtransaction", params)
	if err != nil {
		return nil, 0, err
	}
	var resp struct {
		Hex       string  `json:"hex"`
		Fee       float64 `json:"fee"`
		ChangePos float64 `json:"changepos"`
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, 0, err
	}
	fundedTxBytes, err := hex.DecodeString(resp.Hex)
	if err != nil {
		return nil, 0, err
	}
	fundedTx = &wire.MsgTx{}
	err = fundedTx.Deserialize(bytes.NewReader(fundedTxBytes))
	if err != nil {
		return nil, 0, err
	}
	feeAmount, err := btcutil.NewAmount(resp.Fee)
	if err != nil {
		return nil, 0, err
	}
	return fundedTx, feeAmount, nil
}

// signRawTransaction calls the signRawTransaction JSON-RPC method.  It is
// implemented manually as client support is currently outdated from the
// btcd/rpcclient package.
func signRawTransaction(c *rpc.Client, tx *wire.MsgTx) (fundedTx *wire.MsgTx, complete bool, err error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	param, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, false, err
	}
	rawResp, err := c.RawRequest("signrawtransactionwithwallet", []json.RawMessage{param})
	if err != nil {
		return nil, false, err
	}
	var resp struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, false, err
	}
	fundedTxBytes, err := hex.DecodeString(resp.Hex)
	if err != nil {
		return nil, false, err
	}
	fundedTx = &wire.MsgTx{}
	err = fundedTx.Deserialize(bytes.NewReader(fundedTxBytes))
	if err != nil {
		return nil, false, err
	}
	return fundedTx, resp.Complete, nil
}

// sendRawTransaction calls the signRawTransaction JSON-RPC method.  It is
// implemented manually as client support is currently outdated from the
// btcd/rpcclient package.
func sendRawTransaction(c *rpc.Client, tx *wire.MsgTx) (*chainhash.Hash, error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)

	param, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, err
	}
	hex, err := c.RawRequest("sendrawtransaction", []json.RawMessage{param})
	if err != nil {
		return nil, err
	}
	s := string(hex)
	// we need to remove quotes from the json response
	s = s[1 : len(s)-1]
	hash, err := chainhash.NewHashFromStr(s)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

// getFeePerKb queries the wallet for the transaction relay fee/kB to use and
// the minimum mempool relay fee.  It first tries to get the user-set fee in the
// wallet.  If unset, it attempts to find an estimate using estimatefee 6.  If
// both of these fail, it falls back to mempool relay fee policy.
func getFeePerKb(c *rpc.Client) (useFee, relayFee btcutil.Amount, err error) {
	var netInfoResp struct {
		RelayFee float64 `json:"relayfee"`
	}
	var walletInfoResp struct {
		PayTxFee float64 `json:"paytxfee"`
	}
	var estimateResp struct {
		FeeRate float64 `json:"feerate"`
	}

	netInfoRawResp, err := c.RawRequest("getnetworkinfo", nil)
	if err == nil {
		err = json.Unmarshal(netInfoRawResp, &netInfoResp)
		if err != nil {
			return 0, 0, err
		}
	}
	walletInfoRawResp, err := c.RawRequest("getwalletinfo", nil)
	if err == nil {
		err = json.Unmarshal(walletInfoRawResp, &walletInfoResp)
		if err != nil {
			return 0, 0, err
		}
	}

	relayFee, err = btcutil.NewAmount(netInfoResp.RelayFee)
	if err != nil {
		return 0, 0, err
	}
	payTxFee, err := btcutil.NewAmount(walletInfoResp.PayTxFee)
	if err != nil {
		return 0, 0, err
	}

	// Use user-set wallet fee when set and not lower than the network relay
	// fee.
	if payTxFee != 0 {
		maxFee := payTxFee
		if relayFee > maxFee {
			maxFee = relayFee
		}
		return maxFee, relayFee, nil
	}

	params := []json.RawMessage{[]byte("6")}
	estimateRawResp, err := c.RawRequest("estimatesmartfee", params)
	if err != nil {
		return 0, 0, err
	}

	err = json.Unmarshal(estimateRawResp, &estimateResp)
	if err == nil && estimateResp.FeeRate > 0 {
		useFee, err = btcutil.NewAmount(estimateResp.FeeRate)
		if relayFee > useFee {
			useFee = relayFee
		}
		return useFee, relayFee, err
	}

	fmt.Println("warning: falling back to mempool relay fee policy")
	return relayFee, relayFee, nil
}

// getRawChangeAddress calls the getrawchangeaddress JSON-RPC method.  It is
// implemented manually as the rpcclient implementation always passes the
// account parameter which was removed in Bitcoin Core 0.15.
func getRawChangeAddress(c *rpc.Client) (btcutil.Address, error) {
	params := []json.RawMessage{[]byte(`"legacy"`)}
	rawResp, err := c.RawRequest("getrawchangeaddress", params)
	if err != nil {
		return nil, err
	}
	var addrStr string
	err = json.Unmarshal(rawResp, &addrStr)
	if err != nil {
		return nil, err
	}
	addr, err := btcutil.DecodeAddress(addrStr, chainParams)
	if err != nil {
		return nil, err
	}
	if !addr.IsForNet(chainParams) {
		return nil, fmt.Errorf("address %v is not intended for use on %v",
			addrStr, chainParams.Name)
	}
	if _, ok := addr.(*btcutil.AddressPubKeyHash); !ok {
		return nil, fmt.Errorf("getrawchangeaddress: address %v is not P2PKH",
			addr)
	}
	return addr, nil
}

func promptPublishTx(c *rpc.Client, tx *wire.MsgTx, name string) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Publish %s transaction? [y/N] ", name)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))

		switch answer {
		case "y", "yes":
		case "n", "no", "":
			return nil
		default:
			fmt.Println("please answer y or n")
			continue
		}

		txHash, err := sendRawTransaction(c, tx)
		if err != nil {
			return fmt.Errorf("sendrawtransaction: %v", err)
		}
		fmt.Printf("Published %s transaction (%v)\n", name, txHash)
		return nil
	}
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2SH   btcutil.Address
	contractTxHash *chainhash.Hash
	contractTx     *wire.MsgTx
	contractFee    btcutil.Amount
  feePerKb       btcutil.Amount
}

type builtSpend struct {
  spendTx       *wire.MsgTx
  spendTxHash   []byte
  spendTxFee    btcutil.Amount
  feePerKb btcutil.Amount
}
func getTxHash(tx wire.MsgTx)([]byte){
  var buf bytes.Buffer
  buf.Grow(tx.SerializeSize())
  tx.Serialize(&buf)
  return buf.Bytes()
}
// buildContract creates a contract for the parameters specified in args, using
// wallet RPC to generate an internal address to redeem the refund and to sign
// the payment to the contract transaction.
func buildContract(c *rpc.Client, args *contractArgsCmd) (*builtContract, error) {
	refundAddr, err := getRawChangeAddress(c)
	if err != nil {
		return nil, fmt.Errorf("getrawchangeaddress: %v", err)
	}
	refundAddrH, ok := refundAddr.(interface {
		Hash160() *[ripemd160.Size]byte
	})
	if !ok {
		return nil, errors.New("unable to create hash160 from change address")
	}

	contract, err := atomicSwapContract(refundAddrH.Hash160(), args.them.Hash160(),
		args.locktime, args.secretHash)
	if err != nil {
		return nil, err
	}
	contractP2SH, err := btcutil.NewAddressScriptHash(contract, chainParams)
	if err != nil {
		return nil, err
	}
	contractP2SHPkScript, err := txscript.PayToAddrScript(contractP2SH)
	if err != nil {
		return nil, err
	}

	feePerKb, _, err := getFeePerKb(c)
	if err != nil {
		return nil, err
	}

	unsignedContract := wire.NewMsgTx(txVersion)
	unsignedContract.AddTxOut(wire.NewTxOut(int64(args.amount), contractP2SHPkScript))
	unsignedContract, contractFee, err := fundRawTransaction(c, unsignedContract, feePerKb)
	if err != nil {
		return nil, fmt.Errorf("fundrawtransaction: %v", err)
	}
	contractTx, complete, err := signRawTransaction(c, unsignedContract)
	if err != nil {
		return nil, fmt.Errorf("signrawtransaction: %v", err)
	}
	if !complete {
		return nil, errors.New("signrawtransaction: failed to completely sign contract transaction")
	}

	contractTxHash := contractTx.TxHash()

	return &builtContract{
		contract:       contract,
		contractP2SH:   contractP2SH,
		contractTxHash: &contractTxHash,
		contractTx:     contractTx,
		contractFee:    contractFee,
    feePerKb:       feePerKb,
	}, nil
}

func spendContract(c *rpc.Client, args *spendArgsCmd)(*builtSpend,error) {
  isRedeem := (args.secret != nil)

  pushes, err := txscript.ExtractAtomicSwapDataPushes(0, args.contract)
  if err != nil {
    return nil, err
  }
  if pushes == nil {
    return nil, errors.New("contract is not an atomic swap script recognized by this tool")
  }
  var recipientAddr *btcutil.AddressPubKeyHash
  if isRedeem {
  recipientAddr, err = btcutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
    chainParams)
  }else{
  recipientAddr, err = btcutil.NewAddressPubKeyHash(pushes.RefundHash160[:],
    chainParams)
  }
  if err != nil {
    return nil, err
  }
  contractHash := btcutil.Hash160(args.contract)
  contractOut := -1
  for i, out := range args.contractTx.TxOut {
    sc, addrs, _, _ := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
    if sc == txscript.ScriptHashTy &&
      bytes.Equal(addrs[0].(*btcutil.AddressScriptHash).Hash160()[:], contractHash) {
      contractOut = i
      break
    }
  }
  if contractOut == -1 {
    return nil, errors.New("transaction does not contain a contract output")
  }
  contractOutPoint := wire.OutPoint{
    Hash:  args.contractTx.TxHash(),
    Index: uint32(contractOut),
  }

  addr, err := getRawChangeAddress(c)
  if err != nil {
    return nil, fmt.Errorf("getrawchangeaddress: %v", err)
  }
  outScript, err := txscript.PayToAddrScript(recipientAddr)
  if err != nil {
    return nil, err
  }

	spendTx := wire.NewMsgTx(txVersion)
	spendTx.LockTime = uint32(pushes.LockTime)
	spendTx.AddTxOut(wire.NewTxOut(0, outScript)) // amount set below
  spendSize := 0
  if isRedeem {
    spendSize = estimateRedeemSerializeSize(args.contract, spendTx.TxOut)
  }else{
	  spendSize = estimateRefundSerializeSize(args.contract, spendTx.TxOut)
  }
  feePerKb, minFeePerKb, err := getFeePerKb(c)
  if err != nil {
    return nil, err
  }

	spendFee := txrules.FeeForSerializeSize(feePerKb, spendSize)
	spendTx.TxOut[0].Value = args.contractTx.TxOut[contractOutPoint.Index].Value - int64(spendFee)
	if txrules.IsDustOutput(spendTx.TxOut[0], minFeePerKb) {
		return nil, fmt.Errorf("refund output value of %v is dust", btcutil.Amount(spendTx.TxOut[0].Value))
	}

	txIn := wire.NewTxIn(&contractOutPoint, nil, nil)
	txIn.Sequence = 0
	spendTx.AddTxIn(txIn)

	spendSig, spendPubKey, err := createSig(spendTx, 0, args.contract, addr, c)
	if err != nil {
		return nil, err
	}
  var spendTxSigScript []byte
  if isRedeem {
    spendTxSigScript, err = redeemP2SHContract(args.contract, spendSig, spendPubKey, args.secret)
  } else{
	  spendTxSigScript, err = refundP2SHContract(args.contract, spendSig, spendPubKey)
  }
	if err != nil {
		return nil, err
	}
	spendTx.TxIn[0].SignatureScript = spendTxSigScript

	if verify {
		e, err := txscript.NewEngine(args.contractTx.TxOut[contractOutPoint.Index].PkScript,
			spendTx, 0, txscript.StandardVerifyFlags, txscript.NewSigCache(10),
			txscript.NewTxSigHashes(spendTx), args.contractTx.TxOut[contractOutPoint.Index].Value)
		if err != nil {
			panic(err)
		}
		err = e.Execute()
		if err != nil {
			panic(err)
		}
	}

  var buf bytes.Buffer
  buf.Grow(spendTx.SerializeSize())
  spendTx.Serialize(&buf)

	return &builtSpend{
    spendTx:          spendTx,
    spendTxHash:      buf.Bytes(),
    spendTxFee:       spendFee,
    feePerKb:  feePerKb,
  }, nil
}

func extractSecret(args extractSecretCmd)([]byte,error){
  // Loop over all pushed data from all inputs, searching for one that hashes
  // to the expected hash.  By searching through all data pushes, we avoid any
  // issues that could be caused by the initiator redeeming the participant's
  // contract with some "nonstandard" or unrecognized transaction or script
  // type.
  for _, in := range args.redemptionTx.TxIn {
    pushes, err := txscript.PushedData(in.SignatureScript)
    if err != nil {
      return nil,err
    }
    for _, push := range pushes {
      if bytes.Equal(sha256Hash(push), args.secretHash) {
        return push,nil
      }
    }
  }
  return nil,errors.New("transaction does not contain the secret")

}


func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}

func calcFeePerKb(absoluteFee btcutil.Amount, serializeSize int) float64 {
	return float64(absoluteFee) / float64(serializeSize) / 1e5
}

func (cmd *contractArgsCmd) runCommand(c *rpc.Client) error {
	b, err := buildContract(c, cmd)
	if err != nil {
		return err
	}

	fmt.Printf("secret:      %x\n", cmd.secret)
	fmt.Printf("secret hash: %x\n\n", cmd.secretHash)
	fmt.Printf("contract fee: %v (%0.8f btc/kb)\n", b.contractFee, b.feePerKb)
	fmt.Printf("contract (%v):\n", b.contractP2SH)
	fmt.Printf("%x\n\n", b.contract)
	var contractbuf bytes.Buffer
	contractbuf.Grow(b.contractTx.SerializeSize())
	b.contractTx.Serialize(&contractbuf)
	fmt.Printf("contract transaction (%v):\n", b.contractTxHash)
	fmt.Printf("%x\n\n", contractbuf.Bytes())

	return promptPublishTx(c, b.contractTx, "contract")
}

func (cmd *spendArgsCmd) runCommand(c *rpc.Client) error {
  b,err := spendContract(c,cmd)
	if err != nil {
		return err
	}
  isRedeem := (cmd.secret != nil)
  var tmp string
  if isRedeem {
    tmp = "redeem"
  }else{
    tmp = "refund"
  }
	var buf bytes.Buffer
	buf.Grow(b.spendTx.SerializeSize())
	b.spendTx.Serialize(&buf)
	fmt.Printf("%v fee: %v (%0.8f btc/kb)\n\n", tmp, b.spendTxFee, b.feePerKb)
	fmt.Printf("%v transaction (%v):\n", tmp, &b.spendTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	return promptPublishTx(c, b.spendTx, "redeem")
}

func (cmd *extractSecretCmd) runCommand(c *rpc.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
  b,err := extractSecret(*cmd)
  if err != nil{
    return err
  }
  fmt.Printf("Secret: %x\n", b)
  return nil
}

func (cmd *auditContractCmd) runCommand(c *rpc.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractCmd) runOfflineCommand() error {
	contractHash160 := btcutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
		if err != nil || sc != txscript.ScriptHashTy {
			continue
		}
		if bytes.Equal(addrs[0].(*btcutil.AddressScriptHash).Hash160()[:], contractHash160) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain the contract output")
	}

	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	if pushes.SecretSize != secretSize {
		return fmt.Errorf("contract specifies strange secret size %v", pushes.SecretSize)
	}

	contractAddr, err := btcutil.NewAddressScriptHash(cmd.contract, chainParams)
	if err != nil {
		return err
	}
	recipientAddr, err := btcutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
		chainParams)
	if err != nil {
		return err
	}
	refundAddr, err := btcutil.NewAddressPubKeyHash(pushes.RefundHash160[:],
		chainParams)
	if err != nil {
		return err
	}

	fmt.Printf("contract address:        %v\n", contractAddr)
	fmt.Printf("contract value:          %v\n", btcutil.Amount(cmd.contractTx.TxOut[contractOut].Value))
	fmt.Printf("recipient address:       %v\n", recipientAddr)
	fmt.Printf("author's refund address: %v\n\n", refundAddr)

	fmt.Printf("secret hash: %x\n\n", pushes.SecretHash[:])

	if pushes.LockTime >= int64(txscript.LockTimeThreshold) {
		t := time.Unix(pushes.LockTime, 0)
		fmt.Printf("locktime: %v\n", t.UTC())
		reachedat := time.Until(t).Truncate(time.Second)
		if reachedat > 0 {
			fmt.Printf("locktime reached in %v\n", reachedat)
		} else {
			fmt.Printf("contract refund time lock has expired\n")
		}
	} else {
		fmt.Printf("locktime: block %v\n", pushes.LockTime)
	}

	return nil
}

// atomicswapcontract returns an output script that may be redeemed by one of
// two signature scripts:
//
//   <their sig> <their pubkey> <initiator secret> 1
//
//   <my sig> <my pubkey> 0
//
// the first signature script is the normal redemption path done by the other
// party and requires the initiator's secret.  the second signature script is
// the refund path performed by us, but the refund can only be performed after
// locktime.
func atomicSwapContract(pkhMe, pkhThem *[ripemd160.Size]byte, locktime int64, secretHash []byte) ([]byte, error) {
  b := txscript.NewScriptBuilder()

  b.AddOp(txscript.OP_IF) // Normal redeem path
  {
    // Require initiator's secret to be a known length that the redeeming
    // party can audit.  This is used to prevent fraud attacks between two
    // currencies that have different maximum data sizes.
    b.AddOp(txscript.OP_SIZE)
    b.AddInt64(secretSize)
    b.AddOp(txscript.OP_EQUALVERIFY)

    // Require initiator's secret to be known to redeem the output.
    b.AddOp(txscript.OP_SHA256)
    b.AddData(secretHash)
    b.AddOp(txscript.OP_EQUALVERIFY)

    // Verify their signature is being used to redeem the output.  This
    // would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
    // moved outside of the branch to save a couple bytes.
    b.AddOp(txscript.OP_DUP)
    b.AddOp(txscript.OP_HASH160)
    b.AddData(pkhThem[:])
  }
  b.AddOp(txscript.OP_ELSE) // Refund path
  {
    // Verify locktime and drop it off the stack (which is not done by
    // CLTV).
    b.AddInt64(locktime)
    b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
    b.AddOp(txscript.OP_DROP)

    // Verify our signature is being used to redeem the output.  This would
    // normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been moved
    // outside of the branch to save a couple bytes.
b.AddOp(txscript.OP_DUP)
    b.AddOp(txscript.OP_HASH160)
    b.AddData(pkhMe[:])
  }
  b.AddOp(txscript.OP_ENDIF)

  // Complete the signature check.
  b.AddOp(txscript.OP_EQUALVERIFY)
  b.AddOp(txscript.OP_CHECKSIG)

  return b.Script()
}

// redeemP2SHContract returns the signature script to redeem a contract output
// using the redeemer's signature and the initiator's secret.  This function
// assumes P2SH and appends the contract as the final data push.
func redeemP2SHContract(contract, sig, pubkey, secret []byte) ([]byte, error) {
  b := txscript.NewScriptBuilder()
  b.AddData(sig)
  b.AddData(pubkey)
  b.AddData(secret)
  b.AddInt64(1)
  b.AddData(contract)
  return b.Script()
}

// refundP2SHContract returns the signature script to refund a contract output
// using the contract author's signature after the locktime has been reached.
// This function assumes P2SH and appends the contract as the final data push.
func refundP2SHContract(contract, sig, pubkey []byte) ([]byte, error) {
  b := txscript.NewScriptBuilder()
  b.AddData(sig)
  b.AddData(pubkey)
  b.AddInt64(0)
  b.AddData(contract)
  return b.Script()
}
func restApiRequestsHandlers() {
  http.HandleFunc("/is-online", isOnlineEndpoint)
  http.HandleFunc("/initiate", initiateEnpoint)
  http.HandleFunc("/partecipate", partecipateEndpoint)
  http.HandleFunc("/redeem", redeemEndpoint)
  http.HandleFunc("/refund", refundEndpoint)
  http.HandleFunc("/auditcontract", auditEndpoint)
  http.HandleFunc("/extractsecret", extractSecretEndpoint)
  http.HandleFunc("/pushtx",pushTxEndpoint)
  http.HandleFunc("/walletbalance",walletBalanceEndpoint)
  http.HandleFunc("/newswap",atomicSwapParamsEndpoint)
}
func isOnlineEndpoint(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("content-type", "application/json")
  if isOnline() {
    json.NewEncoder(w).Encode(true)
  } else {
    json.NewEncoder(w).Encode(false)
  }
}

// check if btc / kas network are available

// dummy function  - to be replaced
//todo check kaspad & kaspawallet daemons
func isOnline() bool {
  return true
}
func mainEndpoint(cmd daemonCommand,err error, w http.ResponseWriter, r *http.Request){
}

// initiate swap contract
func initiateEnpoint(w http.ResponseWriter, r *http.Request) {
  buildSwapContractEndpoint(w,r)
}
func partecipateEndpoint(w http.ResponseWriter,r *http.Request){
  buildSwapContractEndpoint(w,r)
}

func redeemEndpoint(w http.ResponseWriter,r *http.Request){
  spendSwapContractEndpoint(w,r)
}

func refundEndpoint(w http.ResponseWriter,r *http.Request){
  spendSwapContractEndpoint(w,r)
}

func auditEndpoint(w http.ResponseWriter,r *http.Request){
  var  args AuditContractInput
  parseBody(r,&args)
  input,err := parseAuditContractArgs(args)
  mainEndpoint(input,err,w,r)
}

func extractSecretEndpoint(w http.ResponseWriter,r *http.Request){
 /* var args extractsecretinput
  parsebody(r,&args)
  input,err := parseextractsecretargs(args)
  data,err := extractsecret(*input)
  writeresult(w,err,extractsecretoutput{secret:fmt.sprintf("%x",data)})
*/
}
func pushTxEndpoint(w http.ResponseWriter,r *http.Request){
}
func walletBalanceEndpoint(w http.ResponseWriter,r *http.Request){
}
func atomicSwapParamsEndpoint(w http.ResponseWriter,r *http.Request){
}
func buildSwapContractEndpoint(w http.ResponseWriter,r *http.Request){
}
func spendSwapContractEndpoint(w http.ResponseWriter,r *http.Request){
}
