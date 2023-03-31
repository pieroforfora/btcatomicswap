package main

import (
  "errors"
  "io/ioutil"
  "net/http"
  "encoding/json"
  "fmt"

)
type AtomicSwapParamsOutput struct {
  ReciptAddress string  `json:"ReciptAddress"`
  MaxSecretLen  string  `json:"MaxSecretLen"`
  MinLockTimeInitiate   string  `json:"MinLockTimeInitiate"`
  MinLockTimePartecipate   string  `json:"MinLockTimePartecipate"`
}

type WalletBalanceOutput struct {
  Available         string             `json:"Available"`
  Pending           string             `json:"Pending"`
  AddressBalances   []*AddressBalance  `json:"Addresses"`
}

type AddressBalance struct {
  Address   string `json:"Address"`
  Available string `json:"Available"`
  Pending   string `json:"Pending"`
}

type BuildContractOutput struct {
  //if partecipate this will be an empty string
  Secret              *string `json:"Secret"`
  SecretHash          string  `json:"SecretHash"`
  Contract            string  `json:"Contract"`
  TxID                string  `json:"ContractTransactionID"`
  Tx                  string  `json:"ContractTransaction"`
  TxFee               string  `json:"TransactionFee"`
}
type BuildContractInput struct {
  Them        string  `json:"RecipientAddress"`
  Amount      string  `json:"Amount"`
  //if nil or empty string I'll initiate a conctract
  //partecipate otherwise
  SecretHash  *string `json:"SecretHash"`
}
type SpendContractOutput struct {
  Tx    string `json:"SpendTransaction"`
  TxID  string `json:"SpendTransactionID"`
  TxFee string `json:"TransactionFee"`
}
type SpendContractInput struct {
  //if nil or empty string I'll start refund
  //redeem otherwise
  Secret    *string `json:"Secret"`
  Contract  string  `json:"Contract"`
  Tx        string  `json:"ContractTransaction"`
}
type AuditContractInput struct {
  Contract  string `json:"Contract"`
  Tx        string `json:"ContractTx"`
}
type  AuditContractOutput struct {
  ContractAddress   string `json:"ContractAddress"`
  //if I don't konw the address this is empty string
  RecipientAddress  string `json:"RecipientAddress"`
  //Recipient2b       string `json:"RecipientBlake2b"`
  Amount            string `json:"ContractAmount"`
  //if I don't konw the address this is empty string
  RefundAddress     string `json:"RefundAddress"`
  //Refund2b          string `json:"RefundBlake2b"`
  SecretHash        string `json:"SecretHash"`
  LockTime          string `json:"LockTime"`
  TxId              string `json:"TxId"`
  //Utxo blockDAAScore
  //DaaScore          string `json:"DaaScore"`
  //virtualSelectedParentBlueScore
  //VSPBS             string `json:"VSPBS"`
  //minConfirmations :=10
  //blockDAAScore+minConfirmations < virtualSelectedParentBlueScore 
  IsSpendable       string `json:"IsSpendable"`
}
type ExtractSecretInput struct {
  Tx          string `json:"Transaction"`
  SecretHash  string `json:"SecretHash"`
}
type ExtractSecretOutput struct {
  Secret  string `json:"Secret"`
}
type PushTxInput struct {
  Tx    string `json:"Tx"`
}
type PushTxOutput struct {
  TxId    string `json:"TxId"`
}
type ErrOutput struct {
  Err string `json:"Err"`
}

func parseBody[V *BuildContractInput | *SpendContractInput | *AuditContractInput | *ExtractSecretInput | *PushTxInput](r *http.Request,args V)(error){
  reqBody, err := ioutil.ReadAll(r.Body)
  if err != nil {
    return errors.New(fmt.Sprintf("failed to read body: %v", err))
  }
  json.Unmarshal(reqBody, &args)
  return nil
}
func writeResult(w http.ResponseWriter, err error, result any){
    w.Header().Set("Content-Type", "application/json")
  if err != nil {
    fmt.Println("/////////////////////////////////error",err)
    json.NewEncoder(w).Encode(ErrOutput{Err:fmt.Sprintf("%v",err)})
  } else {
    json.NewEncoder(w).Encode(result)
  }
}

