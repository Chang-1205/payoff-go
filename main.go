package main


import "fmt"


func main() {
    uid, _ := Enroll()
    fmt.Println("Enrolled user:", uid)


    proof1, _ := CreatePayment(uid, 100)
    fmt.Println("Payment proof:", proof1)


    proof2, _ := OfflineSpend(uid, 50)
    fmt.Println("Offline proof:", proof2)


    proof3, _ := RevokeUser(uid)
    fmt.Println("Revocation proof:", proof3)


    // Simulate double-spend detection
    ledger := []LedgerEntry{
        {Serial: 1111, Tag1: "dS1", Tag2: "dS2"},
        {Serial: 1111, Tag1: "dS1'", Tag2: "dS2'"},
    }
    ds := IdentifyDoubleSpenders(ledger)
    fmt.Println("Double spenders:", ds)


    limitProof, _ := CheckDailyLimit(80, 30, 100)
    fmt.Println("Daily limit proof:", limitProof)
}
