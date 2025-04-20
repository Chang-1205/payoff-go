package main


import (
    "github.com/AlpinYukseloglu/poseidon-gnark/circuits"
    "github.com/consensys/gnark/frontend"
)


type UserCircuit struct {
    ID frontend.Variable `gnark:"secret"`
    H  frontend.Variable `gnark:"public"`
}


func (c *UserCircuit) Define(api frontend.API) error {
    hash := circuits.Poseidon(api, []frontend.Variable{c.ID}) // trả về Variable, không cần index
    api.AssertIsEqual(hash, c.H)
    return nil
}


func Enroll() (string, error) {
    // Tạm thời trả về UID giả lập
    return "fake_uid_123", nil
}
