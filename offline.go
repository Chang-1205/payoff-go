package main


import (
    "bytes"
    "encoding/hex"


    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
)


type OfflineSpendCircuit struct {
    Serial frontend.Variable `gnark:"secret"`
    Amount frontend.Variable `gnark:"public"`
}


func (c *OfflineSpendCircuit) Define(api frontend.API) error {
    api.AssertIsDifferent(c.Serial, 0)
    return nil
}


func OfflineSpend(uid string, amount int) (string, error) {
    assign := OfflineSpendCircuit{Serial: 11111, Amount: amount}
    var circuit OfflineSpendCircuit


    cc, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
        return "", err
    }
    pk, _, err := groth16.Setup(cc)
    if err != nil {
        return "", err
    }
    secretWit, err := frontend.NewWitness(&assign, ecc.BN254.ScalarField())
    if err != nil {
        return "", err
    }
    proof, err := groth16.Prove(cc, pk, secretWit)
    if err != nil {
        return "", err
    }
    var buf bytes.Buffer
    _, err = proof.WriteTo(&buf)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(buf.Bytes()), nil
}
