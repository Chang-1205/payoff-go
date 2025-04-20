package main


func CreatePayment(uid string, amount int) (string, error) {
    return GenPaymentProof(uid, amount)
}
