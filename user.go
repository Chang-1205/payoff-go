package main


import (
    "bytes"
    "encoding/hex"


    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    poseidon "github.com/AlpinYukseloglu/poseidon-gnark/circuits"
)


type EnrollCircuit struct {
    Secret     frontend.Variable `gnark:"secret"`
    Commitment frontend.Variable `gnark:"public"`
}


func (c *EnrollCircuit) Define(api frontend.API) error {
    cm := poseidon.Poseidon(api, []frontend.Variable{c.Secret})
    api.AssertIsEqual(cm, c.Commitment)
    return nil
}


func Enroll() (string, error) {
    var circuit EnrollCircuit
    assignment := EnrollCircuit{Secret: 12345}


    // Compile R1CS
    cc, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
        return "", err
    }


    // Setup proving key
    pk, _, err := groth16.Setup(cc)
    if err != nil {
        return "", err
    }


    // Tính commitment ngoài R1CS
    cm := poseidon.Poseidon(nil, []frontend.Variable{assignment.Secret})
    assignment.Commitment = cm


    // Tạo witness
    secretWit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    if err != nil {
        return "", err
    }


    // Tạo bằng chứng
    proof, err := groth16.Prove(cc, pk, secretWit)
    if err != nil {
        return "", err
    }


    // Chuyển proof sang hex
    var buf bytes.Buffer
    if _, err := proof.WriteTo(&buf); err != nil {
        return "", err
    }


    return hex.EncodeToString(buf.Bytes()), nil
}
