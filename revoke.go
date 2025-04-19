package main


import (
    "bytes"
    "encoding/hex"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
)


type RevokeCircuit struct {
    Key frontend.Variable `gnark:"secret"`
}


func (c *RevokeCircuit) Define(api frontend.API) error {
    api.AssertIsDifferent(c.Key, 0)
    return nil
}


func RevokeUser(uid string) (string, error) {
    var circuit RevokeCircuit
    assign := RevokeCircuit{Key: 99999}


    // Compile the circuit
    cc, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
        return "", err
    }
    // Setup proving key
    pk, _, err := groth16.Setup(cc)
    if err != nil {
        return "", err
    }
    // Create a witness
    secretWit, err := frontend.NewWitness(&assign, ecc.BN254.ScalarField())
    if err != nil {
        return "", err
    }
    // Generate proof
    proof, err := groth16.Prove(cc, pk, secretWit)
    if err != nil {
        return "", err
    }
    // Serialize proof to hex string
    var buf bytes.Buffer
    _, err = proof.WriteTo(&buf)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(buf.Bytes()), nil
}
